package com.soffid.iam.sync.agent.scim;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.wink.client.ClientConfig;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.Resource;
import org.apache.wink.client.RestClient;
import org.apache.wink.client.httpclient.ApacheHttpClientConfig;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReferenceParser;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.MemberAttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class SCIMAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, GroupMgr, RoleMgr,
	AuthoritativeIdentitySource2 {

	protected String EQ_END = "\"";

	private String EQ_BEGIN = " eq \"";

	private static final long serialVersionUID = 1L;

	protected ValueObjectMapper vom = new ValueObjectMapper();
	
	protected ObjectTranslator objectTranslator = null;
	
	protected boolean debugEnabled;
	
	boolean wso2workaround;

	/** Usuario root de conexión LDAP */
	String loginDN;
	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	Password password;
	/** HOST donde se aloja LDAP */
	String serverUrl;
	
	String authMethod;
	
	String authUrl;
	
	String scimVersion;
	
	String contentType;

	protected Collection<ExtensibleObjectMapping> objectMappings;
	// --------------------------------------------------------------

	private ClientConfig config;

	protected RestClient client;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public SCIMAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SCIM agent on {}", getDispatcher().getCodi(),
				null);
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1());
		authMethod = getDispatcher().getParam2();
		authUrl = getDispatcher().getParam3();
		serverUrl = getDispatcher().getParam4();
		debugEnabled = "true".equals(getDispatcher().getParam8());
		wso2workaround = "true".equals(getDispatcher().getParam9());

		if (wso2workaround) 
		{
			EQ_BEGIN = "Eq";
			EQ_END = "";
		}
		// create a client to send the user/group crud requests
		config = new ApacheHttpClientConfig(new DefaultHttpClient());
		if ("tokenBasic".equals(authMethod))
		{
			TokenBasicHandler handler = new TokenBasicHandler(authUrl, loginDN, password.getPassword());
			config.handlers(handler);
		}
		if ("token".equals(authMethod))
		{
			TokenHandler handler = new TokenHandler (authUrl, loginDN, password.getPassword());
			config.handlers(handler);
		}
		if ("basic".equals(authMethod))
		{
			BasicAuthSecurityHandler handler = new BasicAuthSecurityHandler(loginDN, password.getPassword());
			config.handlers(handler);
		}
		
		client = new RestClient(config);
	}

	protected boolean moreData = false;
	protected String nextChange = null;
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
				{
					String property = mapping.getProperties().get("changeProperty");
					ClientResponse response;
					String path;
					
					if (property != null)
					{
						AttributeReference ar = AttributeReferenceParser.parse(null, property);
						String ft = getJsonReference(ar);
						String query = ft+" gt \""+lastChange+EQ_END;
						path = getObjectPath(mapping.getSystemObject())+"?filter="+query+"&sortBy="+ft+"&sortOrder=ascending";
					}
					else
						path = getObjectPath(mapping.getSystemObject())+"?filter=&sortBy=&sortOrder=";

					if (debugEnabled)
						log.info("Querying for authoritative changes: "+path);
						
					response = client
							.resource(path)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED)
							.accept(MediaType.APPLICATION_JSON)
							.get();
					if (response.getStatusCode() != HttpStatus.OK.getCode())
					{
						response.consumeContent();
						throw new InternalErrorException ("Unexpected status "+
								response.getStatusCode()+":"+
								response.getStatusType().getReasonPhrase()+" on "+
								path);
					}
					JSONObject respOb  = response.getEntity(JSONObject.class);
					JSONArray array = respOb.optJSONArray("Resources");
					if (array == null)
							throw new InternalErrorException ("Expecting a JSON array from path "+path+ " and got "+respOb.toString(2));
					for (int i = 0; i < array.length(); i++)
					{
						JSONObject inputJsonObject = array.getJSONObject(i);
						if (debugEnabled)
							log.info ("Got object "+inputJsonObject.toString(15));
						ExtensibleObject inputExtensibleObject = new ExtensibleObject();
						inputExtensibleObject.setObjectType(mapping.getSystemObject());
						json2map(inputJsonObject, inputExtensibleObject);
						ExtensibleObject translatedExtensibleObject = objectTranslator.parseInputObject(inputExtensibleObject, mapping);
						AuthoritativeChange change = vom.parseAuthoritativeChange(translatedExtensibleObject);
						if ( change != null)
						{
							if (debugEnabled)
								log.info("Translated to "+change.toString());
							if (property != null)
								nextChange = (String) AttributeReferenceParser.parse(inputExtensibleObject, property).getValue();
							changes.add(change);
						}
						else if (debugEnabled)
							log.info ("Does not translate to a user change");
							
						if (changes.size() > 100)
						{
							if (debugEnabled)
								log.info ("More than 100 records got. Exiting");
							moreData = true;
							break;
						}
					}
				}
			}
			moreData = false;
			return changes;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	public String getNextChange() throws InternalErrorException {
		return nextChange;
	}

	public boolean hasMoreData() throws InternalErrorException {
		return moreData;
	}

	public void removeRole(String name, String system) throws RemoteException,
			InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(name);
		if (getCodi().equals(system))
		{
			rol.setBaseDeDades(system);
			
			ExtensibleObject roleObject = new RoleExtensibleObject(rol,
							getServer());
			try {
				for (ExtensibleObjectMapping eom: objectMappings)
				{
					if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
					{
						if (! "true".equals( eom.getProperties().get("preventDeletion")))
						{
							String condition = eom.getCondition();
							eom.setCondition(null);
							try {
								ExtensibleObject obj = objectTranslator.generateObject(roleObject, eom);
								if (obj != null)
									removeObject(roleObject, obj);
							} finally { 
								eom.setCondition(condition);
							}
						}
					}
				}
			}
			catch (InternalErrorException e)
			{
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			}
		}
	}

	private void removeObjects(ExtensibleObject soffidObject, ExtensibleObjects objects) throws InternalErrorException {
		for (ExtensibleObject obj: objects.getObjects())
		{
			removeObject (soffidObject, obj);
		}
	}

	protected void removeObject(ExtensibleObject soffidObject, ExtensibleObject object) throws InternalErrorException {
		try
		{
			ExtensibleObject existingObject = searchJsonObject(object);
			if (existingObject != null)
			{
				debugObject("Removing object",existingObject, "");

				String id =  (String) existingObject.get("id").toString();
				
				String path = getObjectPath(object)+"/"+id;

				object.setAttribute("id", id);

				if (debugEnabled)
					log.info ("Path: "+path);
				JSONObject obj = (JSONObject) java2json(object);
				
				if (preDelete(soffidObject, existingObject))
				{
			
					ClientResponse response = client
							.resource(path)
							.delete();
					if (response.getStatusCode() != HttpStatus.OK.getCode() &&
							response.getStatusCode() != HttpStatus.NO_CONTENT.getCode())
					{
						response.consumeContent();
						throw new InternalErrorException ("Unexpected status "+
								response.getStatusCode()+":"+
								response.getStatusType().getReasonPhrase()+" on "+
								path);
					}
					// If the response is no content, it should not be parsed
					if (response.getStatusCode() == HttpStatus.OK.getCode())
					{
						if (wso2workaround)
							response.consumeContent();
						else
						{
							JSONObject result = response.getEntity(JSONObject.class);
							if (debugEnabled)
							{
								log.info ("Response :"+ result.toString(10));
							}
							JSONArray errors = result.optJSONArray("Errors");
							if (errors != null)
								throw new InternalErrorException ("Error deletinc object: "+errors);
						}
					}
					postDelete(soffidObject, existingObject);
				}
			}
		}
		catch (Exception e)
		{
			String msg = "updating object : " + object.toString();
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi()))
		{
			try
			{
				RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol,
						getServer());
				debugObject("Updating role",sourceObject, "");
	
				for (ExtensibleObjectMapping mapping: objectMappings)
				{
					if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
					{
						if (objectTranslator.evalCondition(sourceObject, mapping))
						{
			    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
			    			if (obj != null)
			    				updateObject(sourceObject, obj);
						}
						else
						{
							removeRole(rol.getNom(), rol.getBaseDeDades());
						}
					}
				}
			}
			catch (InternalErrorException e)
			{
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			}
		}
	}

	public void removeGroup(String name) throws RemoteException,
			InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(name);
		GroupExtensibleObject groupObject = new GroupExtensibleObject(grup,
				getDispatcher().getCodi(), getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(groupObject, eom);
						if (obj != null)
							removeObject(groupObject, obj);
					} finally { 
						eom.setCondition(condition);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateGroup(String name, Grup group) throws RemoteException,
			InternalErrorException {

		try {
			GroupExtensibleObject sourceObject = new GroupExtensibleObject(group, getCodi(), 
					getServer());
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP))
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeGroup(name);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	@SuppressWarnings("rawtypes")
	public List<RolGrant> getAccountGrants(String accountName) throws RemoteException,
			InternalErrorException {
		Account account = new Account();
		account.setName(accountName);
		account.setDispatcher(getCodi());
		account.setDisabled(false);
	
		List<RolGrant> grants = new LinkedList<RolGrant>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject scimObj = objectTranslator.generateObject(new AccountExtensibleObject(account, getServer()), mapping);
						if (scimObj != null)
						{
							ExtensibleObject scimStoredObject = searchJsonObject(scimObj);
							if (scimStoredObject != null)
							{
								String multidomain = mapping.getProperties().get("multidomain");

								if ("true".equals(multidomain)) {
									@SuppressWarnings("unchecked")
									HashMap hm = (HashMap) scimStoredObject.get("urn:scim:schemas:extension:custom:1.0");
									if (hm != null) {
										List<HashMap> lhm = (List<HashMap>) hm.get("customers");
										for (HashMap ihm : lhm) {
											Object holder = (Object) ihm.get("code");
											if (holder instanceof JSONObject)
												break;
											List<String> lhm2 = (List<String>) ihm.get("groups");
											for (String role : lhm2) {
												if (role.isEmpty())
													break;
												RolGrant rg = new RolGrant();
												rg.setDispatcher(getCodi());
												rg.setEnabled(true);
												rg.setOwnerAccountName(accountName);
												rg.setOwnerDispatcher(getCodi());
												rg.setRolName(role);
												rg.setHolderGroup(holder.toString());
												rg.setDomainValue(holder.toString());
												grants.add(rg);
											}
										}
									}
								} else {
									@SuppressWarnings("unchecked")
									List<Object> groups = (List<Object>) scimStoredObject.get("groups");
									if (groups != null)
									{
										for (Object group: groups)
										{
											String id;
											String ref= null;
											if (group instanceof Map)
											{
												id = (String) ((Map)group).get("value");
												if (id == null)
													id = (String) ((Map)group).get("id");
												ref = (String) ((Map)group).get("ref");
												if (ref == null)
													ref = (String) ((Map)group).get("$ref");
											}
											else
												id = group.toString();
											if (ref != null || id != null)
											{
												for (ExtensibleObjectMapping roleMapping: objectMappings)
												{
													if ( roleMapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
													{
														if (ref == null)
															ref = getObjectPath(roleMapping.getSystemObject()) + "/"+id;

														ClientResponse response = client
																.resource(ref)
																.accept(MediaType.APPLICATION_JSON)
																.get();
														if (response.getStatusCode() != HttpStatus.OK.getCode())
														{
															response.consumeContent();
															throw new InternalErrorException ("Unexpected status "+
																	response.getStatusCode()+":"+
																	response.getStatusType().getReasonPhrase()+" on "+
																	ref);
														}

														ExtensibleObject gotRole = new ExtensibleObject();
														gotRole.setObjectType(roleMapping.getSystemObject());
														json2map(response.getEntity(JSONObject.class), gotRole);
														Rol r = vom.parseRol(objectTranslator.parseInputObject(gotRole,roleMapping));
														if (r != null)
														{
															RolGrant rg = new RolGrant();
															rg.setDispatcher(getCodi());
															rg.setEnabled(true);
															rg.setOwnerAccountName(accountName);
															rg.setOwnerDispatcher(getCodi());
															rg.setRolName(r.getNom());
															grants.add(rg);
														}
													}
												}
											}
										}
									}
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
		return grants;
	}

	public Account getAccountInfo(String accountName) throws RemoteException,
			InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					Account acc = new Account ();
					acc.setName(accountName);
					acc.setDispatcher(getCodi());
					acc.setDisabled(false);
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject scimObj = objectTranslator.generateObject(new AccountExtensibleObject(acc, getServer()), mapping);
						if (scimObj != null)
						{
							if (debugEnabled)
								debugObject("Looking for object", scimObj, "");
							ExtensibleObject scimStoredObject = searchJsonObject(scimObj);
							if (scimStoredObject != null)
							{
								debugObject("got object", scimStoredObject, "");
								
								acc = vom.parseAccount( objectTranslator.parseInputObject(scimStoredObject, mapping));
								if (acc != null)
									return acc;
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
		return null;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
				{
					String path = getObjectPath(mapping.getSystemObject());
					if ( !wso2workaround)
						path = path + "?filter=&sortBy=&sortOrder=";
					if (debugEnabled)
						log.info("Querying for role list: "+path);
					ClientResponse response = client
							.resource(path)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED)
							.accept(MediaType.APPLICATION_JSON)
							.get();
					if (wso2workaround && 
							response.getStatusCode() == HttpStatus.NOT_FOUND.getCode())
					{
						// No role exists yet
						response.consumeContent();
					} else if (response.getStatusCode() != HttpStatus.OK.getCode())
					{
						response.consumeContent();
						throw new InternalErrorException ("Unexpected status "+
								response.getStatusCode()+":"+
								response.getStatusType().getReasonPhrase()+" on "+
								path);
					} else {
						JSONObject respOb  = response.getEntity(JSONObject.class);
						JSONArray array = respOb.optJSONArray("Resources");
						if (array == null)
								throw new InternalErrorException ("Expecting a JSON array from path "+path+ " and got "+respOb.toString(2));
						if (debugEnabled)
							log.info("Got "+array.length()+" accounts");
						for (int i = 0; i < array.length(); i++)
						{
							JSONObject inputJsonObject = array.getJSONObject(i);
							if (debugEnabled)
								log.info("Got JSON Object "+inputJsonObject.toString(2));
							ExtensibleObject inputExtensibleObject = new ExtensibleObject();
							inputExtensibleObject.setObjectType(mapping.getSystemObject());
							json2map(inputJsonObject, inputExtensibleObject);
							String accountName = (String) objectTranslator.parseInputAttribute("accountName", inputExtensibleObject, mapping);
							if (debugEnabled)
								log.info ("Soffid account name="+accountName);
							if ( accountName != null)
								accounts.add(accountName);
						}
					}
				}
			}
			moreData = false;
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
				{
					Rol role = new Rol();
					role.setNom(roleName);
					role.setBaseDeDades(getCodi());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject scimObj = objectTranslator.generateObject(new RoleExtensibleObject(role, getServer()), mapping);
						if (scimObj != null)
						{
							debugObject("Searching for role "+role+":", scimObj, "");
							ExtensibleObject scimStoredObject = searchJsonObject(scimObj);
							if (scimStoredObject != null)
							{
								debugObject("Got SCIM object", scimStoredObject, "");
								ExtensibleObject parseInputObject = objectTranslator.parseInputObject(scimStoredObject, mapping);
								debugObject("Parsed soffid role:", parseInputObject, "");
								role  = vom.parseRol(parseInputObject);
								if (role != null)
								{
									if (debugEnabled)
										log.info("Result: "+role.toString());
									return role;
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
				{
					String path = getObjectPath(mapping.getSystemObject());
					if ( !wso2workaround)
						path = path + "?filter=&sortBy=&sortOrder=";
					if (debugEnabled)
						log.info("Querying for role list: "+path);
					ClientResponse response = client
							.resource(path)
							.contentType(MediaType.APPLICATION_FORM_URLENCODED)
							.accept(MediaType.APPLICATION_JSON)
							.get();
					if (wso2workaround && 
							response.getStatusCode() == HttpStatus.NOT_FOUND.getCode())
					{
						// No role exists yet
						response.consumeContent();
					} else if (response.getStatusCode() != HttpStatus.OK.getCode())
					{
						response.consumeContent();
						throw new InternalErrorException ("Unexpected status "+
								response.getStatusCode()+":"+
								response.getStatusType().getReasonPhrase()+" on "+
								path);
					} else {
						JSONObject respOb  = response.getEntity(JSONObject.class);
						JSONArray array = respOb.optJSONArray("Resources");
						if (array == null)
								throw new InternalErrorException ("Expecting a JSON array from path "+path+ " and got "+respOb.toString(2));
						if (debugEnabled)
							log.info("Got "+array.length()+" roles");
						for (int i = 0; i < array.length(); i++)
						{
							JSONObject inputJsonObject = array.getJSONObject(i);
							ExtensibleObject inputExtensibleObject = new ExtensibleObject();
							inputExtensibleObject.setObjectType(mapping.getSystemObject());
							json2map(inputJsonObject, inputExtensibleObject);
							String accountName = (String) objectTranslator.parseInputAttribute("name", inputExtensibleObject, mapping);
							if ( accountName != null)
							{
								accounts.add(accountName);
								if (debugEnabled)
									log.info ("Parsed role "+ accountName);
							}
							else
							{
								if (debugEnabled)
									log.info ("Unable to parse role name from JSON object:"+ inputJsonObject.toString(4));
							}
						}
					}
				}
			}
			moreData = false;
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		if (acc == null)
			removeScimUser(accountName);
		else
		{
			try {
				Usuari u = getServer().getUserInfo(accountName, getCodi());
				updateUser (acc, u);
			} catch (UnknownUserException e) {
				updateUser (acc);
			}
		}
	}
		
	public void removeScimUser(String accountName) throws RemoteException,
		InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
		ExtensibleObject userObject = new AccountExtensibleObject(acc,
						getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(userObject, eom);
						if (obj != null)
							removeObject(userObject, obj);
					} finally { 
						eom.setCondition(condition);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUser(Account acc, Usuari user) throws RemoteException,
			InternalErrorException {
		ExtensibleObject sourceObject = new UserExtensibleObject(acc, user, getServer());
		sourceObject.setAttribute("password", getServer().getOrGenerateUserPassword(acc.getName(), getCodi()).getPassword());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeScimUser(acc.getName());
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUser(Account acc) throws InternalErrorException {
		
		ExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
		sourceObject.setAttribute("password", getServer().getOrGenerateUserPassword(acc.getName(), getCodi()).getPassword());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeScimUser(acc.getName());
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUserPassword(String accountName, Usuari user, Password password,
			boolean mustChange) throws RemoteException, InternalErrorException {
		Account acc = new Account ();
		acc.setName(accountName);
		if (user != null)
			acc.setDescription(user.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject object = user == null ?
				new AccountExtensibleObject(acc, getServer()) :
				new UserExtensibleObject(acc, user, getServer());
		object.setAttribute("password", password.getPassword());
		object.setAttribute("mustChange", mustChange);
		ExtensibleObjects objects =
				objectTranslator.generateObjects(object);
		try {
			updateObjects(object, objects);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public boolean validateUserPassword(String arg0, Password arg1)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> mapping)
			throws RemoteException, InternalErrorException {
		this.objectMappings = mapping;
		this.objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), mapping);
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			
			public Collection<Map<String,Object>> invoke (String verb, String command, Map<String, Object> params) throws InternalErrorException
			{
				if (debugEnabled)
				{
					log.info ("Invoking: "+verb+" on "+command);
				}

				Resource resource = client
						.resource(command)
						.contentType(MediaType.APPLICATION_JSON)
						.accept(MediaType.APPLICATION_JSON);
				
				JSONObject result = resource.invoke( verb, JSONObject.class,  
						params == null ? null : new JSONObject(params));
				
				if (debugEnabled && result != null)
				{
					try {
						log.info ("Result: "+result.toString(10));
					} catch (JSONException e) {
						log.info("Error displaying response: ", e);
					}
				}
				
				HashMap<String, Object> eo = new HashMap<String, Object>();
				try {
					json2map (result, eo);
				} catch (JSONException e) {
					throw new InternalErrorException("Error decoding response", e);
				}
				LinkedList<Map<String,Object>> r = new LinkedList<Map<String,Object>>();
				r.add(eo);
				return r;
			}

			public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
				return searchJsonObject(pattern);
			}
		});
	}


	public void updateObjects (ExtensibleObject soffidObject, ExtensibleObjects objects)
			throws Exception
	{

		for (ExtensibleObject object : objects.getObjects())
		{
			updateObject(soffidObject, object);
		}
	}

	
	protected ExtensibleObject searchJsonObject (ExtensibleObject object) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		ExtensibleObjectMapping mapping = getMapping(object.getObjectType());
		if (mapping == null)
		{
			throw new InternalErrorException ("Unable to find mapping for object type "+object.getObjectType());
		}
		String attribute = mapping.getProperties().get("keyAttribute");
		if (attribute == null)
			attribute = "externalId";

		AttributeReference ar = AttributeReferenceParser.parse(object, attribute);
		Object key = ar.getValue();
		if (key == null)
		{
			if (debugEnabled)
			{
				log.info ("Cannot locate object. Attribute "+attribute+" is null");
			}
			return null;
		}
		
		String ft = getJsonReference(ar);
		
		String path = getObjectPath(object) + "?filter="+URLEncoder.encode(ft+EQ_BEGIN+key.toString()+EQ_END, "UTF-8")+"&sortBy=&sortOrder=";
		
		if (debugEnabled)
			log.info ("Searching for object. Path: "+path);
		ClientResponse response = client
				.resource(path)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.get();
		
		if (wso2workaround && response.getStatusCode() == HttpStatus.NOT_FOUND.getCode())
		{
			response.consumeContent();
			return null;
		}
		if (response.getStatusCode() != HttpStatus.OK.getCode())
		{
			response.consumeContent();
			throw new RuntimeException("Error on invocation "+response.getMessage());
		}
		
		JSONObject respOb  = response.getEntity(JSONObject.class);
		JSONArray array = respOb.optJSONArray("Resources");
		if (array == null)
				throw new InternalErrorException ("Expecting a JSON array from path "+path+ " and got "+respOb.toString(2));
		if ( array.length() == 0)
			return null;
		else if ( array.length() > 1)
		{
			throw new InternalErrorException ("Expected one object, and got "+array.length()+" when invoking "+path+":\n"
					+ array.toString(5));
		}
		else 
		{
			ExtensibleObject eo = new ExtensibleObject ();
			eo.setObjectType(object.getObjectType());
			json2map ((JSONObject) array.get(0), eo);
			return eo;
		}
	}

	protected String getJsonReference(AttributeReference ar) {
		String ft = null;
		while (ar != null)
		{
			if (ar instanceof MemberAttributeReference)
			{
				if (ft == null)
					ft = ((MemberAttributeReference) ar).getMember();
				else
					ft = ((MemberAttributeReference) ar).getMember()+"."+ft;
			}
			ar = ar.getParentReference();
		}
		return ft;
	}

	@SuppressWarnings("rawtypes")
	protected void json2map(JSONObject jsonObject, Map<String,Object> map) throws JSONException 
	{
		for ( Iterator it = jsonObject.keys(); it.hasNext(); )
		{
			String key = (String) it.next();
			Object value = jsonObject.get(key);
			map.put(key, json2java(value));
		}
		
	}

	private Object json2java(Object jsonObject) throws JSONException {
		if (jsonObject instanceof JSONObject)
		{
			Map<String,Object> map2 = new HashMap<String, Object>();
			json2map((JSONObject) jsonObject, map2);
			return map2;
		}
		else if (jsonObject instanceof JSONArray)
		{
			List<Object> list = new LinkedList<Object>();
			json2list((JSONArray) jsonObject, list);
			return list;
		}
		else
			return jsonObject;
	}

	private void json2list(JSONArray array, List<Object> list) throws JSONException {
		for (int i = 0;  i < array.length(); i ++)
		{
			Object value = array.get(i);
			list.add( json2java (value));
		}
	}

	@SuppressWarnings("rawtypes")
	private void map2json(Map<String,Object> map, JSONObject jsonObject) throws JSONException 
	{
		for ( Iterator it = map.keySet().iterator(); it.hasNext(); )
		{
			String key = (String) it.next();
			Object value = map.get(key);
			jsonObject.put(key, java2json(value));
		}
		
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private Object java2json(Object javaObject) throws JSONException {
		if (javaObject instanceof Map)
		{
			JSONObject jsonObject = new JSONObject();
			map2json((Map) javaObject, jsonObject);
			return jsonObject;
		}
		else if (javaObject instanceof JSONArray)
		{
			JSONArray jsonArray = new JSONArray();
			list2json ((List) javaObject, jsonArray);
			return jsonArray;
		}
		else
			return javaObject;
	}

	private void list2json(List<Object> list, JSONArray array) throws JSONException {
		for (Object javaObject: list)
		{
			array.put(java2json(javaObject));
		}
	}

	private String getObjectPath(ExtensibleObject object) {
		return getObjectPath(object.getObjectType());
	}

	protected String getObjectPath(String objectType) {
		String path = getMapping(objectType).getProperties().get("path");
		if (path == null)
			path = objectType;
		if (path.startsWith("/") && serverUrl.endsWith("/"))
			return serverUrl + path.substring(1);
		else if (path.startsWith("/") || serverUrl.endsWith("/"))
			return serverUrl + path;
		else
			return serverUrl + "/" + path;
	}

	protected void updateObject (ExtensibleObject soffidObject, ExtensibleObject object)
			throws InternalErrorException
	{
		try
		{
			ExtensibleObject existingObject = searchJsonObject(object);
			if (existingObject == null)
			{
				String path = getObjectPath(object);

				JSONObject obj = (JSONObject) java2json(object);
				
				if (preInsert(soffidObject, object))
				{
					debugObject("Creating object",object, "");
					ClientResponse response = client
							.resource(path)
							.contentType(MediaType.APPLICATION_JSON)
							.accept(MediaType.APPLICATION_JSON)
							.post(  obj );
					if (response.getStatusCode() != HttpStatus.OK.getCode() &&
							response.getStatusCode() != HttpStatus.CREATED.getCode())
					{
						throw new InternalErrorException ("Unexpected status "+
								response.getStatusCode()+":"+
								response.getStatusType().getReasonPhrase()+" on "+
								path+":\n"+response.getEntity(String.class));
					}
					JSONObject result = response.getEntity(JSONObject.class);
					if (debugEnabled)
					{
						log.info ("Result: "+result.toString(10));
					}
					JSONArray errors = result.optJSONArray("Errors");
					if (errors != null)
						throw new InternalErrorException ("Error creating object: "+errors);
					postInsert(soffidObject, object, object);
				}
			}
			else
			{
				String id =  existingObject.get("id").toString();
				
				String path = getObjectPath(object)+"/"+id;

				boolean anyChange = false;
				for (String tag: object.keySet())
				{
					if (!existingObject.containsKey(tag) ||
						(existingObject.get(tag) == null && object.get(tag) != null) ||
						!existingObject.get(tag).equals(object.get(tag)))
					{
						existingObject.put(tag, object.get(tag));
						anyChange = true;
					}
				}
				if (!anyChange)
				{
					debugObject("No need to update object",object, "");
					return;
				}
				if (preUpdate(soffidObject, object, existingObject))
				{
					debugObject("Updating object",object, "");
					if (debugEnabled)
						log.info ("Path = "+path);
	
					JSONObject obj = (JSONObject) java2json(existingObject);
					
					JSONObject result;
					ClientResponse response = client
								.resource(path)
								.contentType(MediaType.APPLICATION_JSON)
								.accept(MediaType.APPLICATION_JSON)
								.put(obj);
	/*
	 * 				if (response.getStatusCode() == HttpStatus.FORBIDDEN.getCode())
					{
						response.consumeContent();
						try {
							result = client
								.resource(path)
								.contentType(MediaType.APPLICATION_JSON)
								.accept(MediaType.APPLICATION_JSON)
								.invoke ("PATCH", JSONObject.class, obj);
						} catch (ClientWebException e) {
							throw new InternalErrorException ("Unexpected status "+
									e.getResponse().getStatusCode()+":"+
									e.getResponse().getStatusType().getReasonPhrase()+" on "+
									path);
						}
					}
					else
					*/
					if (response.getStatusCode() != HttpStatus.OK.getCode())
						throw new InternalErrorException ("Unexpected status "+
									response.getStatusCode()+":"+
									response.getStatusType().getReasonPhrase()+" on "+
									path+":\n"+response.getEntity(String.class));
					else 
						result = response.getEntity(JSONObject.class);
	
					if (debugEnabled)
					{
						log.info ("Result: "+result.toString(10));
					}
					JSONArray errors = result.optJSONArray("Errors");
					if (errors != null)
						throw new InternalErrorException ("Error creating object: "+errors);
					postUpdate(soffidObject, object, existingObject);
				}
			}
		}
		catch (Exception e)
		{
			String msg = "updating object : " + object.toString();
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
	}

	protected ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map: objectMappings)
		{
			if ( map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}
	
	void debugObject (String msg, Object obj, String indent)
	{
		debugObject(msg, obj, indent, "");
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	void debugObject (String msg, Object obj, String indent, String attributeName)
	{
		if (debugEnabled)
		{
			if (msg != null)
				log.info(indent + msg);
			if (obj == null)
			{
				log.info (indent+attributeName.toString()+": null");
			}
			else if (obj instanceof List)
			{
				log.info (indent+attributeName+"List [");
				List l = (List) obj;
				int i = 0;
				for (Object subObj2: l)
				{
					debugObject (null, subObj2, indent+"   ", ""+(i++)+": ");
				}
				log.info (indent+"]");
				
			}
			else if (obj instanceof Map)
			{
				log.info (indent+attributeName+":");
				Map<String,Object> m = (Map<String, Object>) obj;
				for (String attribute: m.keySet())
				{
					Object subObj = m.get(attribute);
					debugObject(null, subObj, indent+"   ", attribute+": ");
				}
			}
			else
			{
				log.info (indent+attributeName.toString()+obj.toString());
			}
		}
	}
	
	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String account, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		updateUser (acc, usu);
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			removeScimUser(account);
		else
			updateUser (acc);
	
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject newObject,
			ExtensibleObject oldObject) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (newObject == null || newObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", newObject);
						if ( oldObject != null)
						{
							eo.setAttribute("oldObject", oldObject);
						}
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								if (oldObject != null)
									debugObject("old object", oldObject, "  ");
								if (newObject != null)
									debugObject("new object", newObject, "  ");
							}
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, adObject, null);
	}

	protected boolean preDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, null, currentEntry);
	}

	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, adObject, currentEntry);
	}

	protected boolean postDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject,  null, currentEntry);
	}
}
	
