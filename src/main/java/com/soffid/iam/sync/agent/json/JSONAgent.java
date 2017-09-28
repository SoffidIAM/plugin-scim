package com.soffid.iam.sync.agent.json;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
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

import com.soffid.iam.api.RoleGrant;

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
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReferenceParser;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
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

public class JSONAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, GroupMgr, RoleMgr,
	AuthoritativeIdentitySource2 {

	private static final long serialVersionUID = 1L;

	protected ValueObjectMapper vom = new ValueObjectMapper();
	
	protected ObjectTranslator objectTranslator = null;
	
	boolean debugEnabled;
	
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

	private RestClient client;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public JSONAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting JSON agent on {}", getDispatcher().getCodi(),
				null);
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1());
		authMethod = getDispatcher().getParam2();
		authUrl = getDispatcher().getParam3();
		serverUrl = getDispatcher().getParam4();
		debugEnabled = "true".equals(getDispatcher().getParam8());

		// create a client to send the user/group crud requests
		config = new ApacheHttpClientConfig(new DefaultHttpClient());
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

	boolean moreData = false;
	String nextChange = null;
	@SuppressWarnings("unchecked")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
				{
					for (InvocationMethod m: getMethods(mapping.getSystemObject(), "select"))
					{
						ExtensibleObject object = new ExtensibleObject();
						ExtensibleObjects objects = invoke (m, object);
						if (objects != null)
						{
							for (ExtensibleObject eo: objects.getObjects())
							{
								ExtensibleObject soffidUser = objectTranslator.parseInputObject(eo, mapping);
								Usuari u = vom.parseUsuari(soffidUser);
								if (u != null)
								{
									AuthoritativeChange ch = new AuthoritativeChange();
									ch.setUser(u);
									ch.setAttributes((Map<String, Object>) soffidUser.getAttribute("attributes"));
									changes.add(ch);
								}
									
							}
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

	private void removeObjects(ExtensibleObject soffidObject, ExtensibleObjects targetObjects) throws InternalErrorException {
		for (ExtensibleObject obj: targetObjects.getObjects())
		{
			removeObject (soffidObject, obj);
		}
	}

	protected void removeObject(ExtensibleObject soffidObject, ExtensibleObject object) throws InternalErrorException {
		try
		{
			debugObject("Removing object", object, "");
			
			for (ExtensibleObject targetObject: objectTranslator.generateObjects(object).getObjects())
			{
				ExtensibleObject existingObject = searchJsonObject(targetObject);
			
				if (existingObject != null)
				{
					for (InvocationMethod m: getMethods(targetObject.getObjectType(), "delete"))
					{
						if (runTrigger(SoffidObjectTrigger.PRE_DELETE, object, targetObject, existingObject))
						{
							invoke (m, object);
							runTrigger(SoffidObjectTrigger.POST_DELETE, object, targetObject, existingObject);
						}
					}
				}
			}
		}
		catch (Exception e)
		{
			String msg = "removing object : " + object.toString();
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

	public List<RolGrant> getAccountGrants(String accountName) throws RemoteException,
			InternalErrorException {
		Account account = new Account();
		account.setName(accountName);
		account.setDispatcher(getCodi());
		account.setDisabled(false);
	
		List<RolGrant> grants = new LinkedList<RolGrant>();
		
		if (!tryGrantFetch (accountName, grants))
			tryAccountFetch (accountName, grants);
		
		
		return grants;
	}

	private boolean tryAccountFetch(String accountName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_ACCOUNT)) {
					Account acc = getServer()
							.getAccountInfo(accountName, getCodi());
					ExtensibleObject obj = objectTranslator.generateObject(
							new AccountExtensibleObject(acc, getServer()), mapping);
					if (obj != null) {
						obj = searchJsonObject(obj);
						if (obj != null) {
							ExtensibleObject soffidObject = objectTranslator
									.parseInputObject(obj, mapping);
							if (soffidObject != null) {
								List<Map<String, Object>> grantedRoles = (List<Map<String, Object>>) soffidObject
										.get("grantedRoles");
								if (grantedRoles != null) {
									for (Map<String, Object> grantedRole : grantedRoles) {
										RolGrant grant = vom
												.parseGrant(grantedRole);
										grants.add(grant);
									}
									found = true;
								}
								List<String> granted = (List<String>) soffidObject
										.get("granted");
								if (granted != null) {
									for (String grantedRole : granted) {
										RolGrant grant = new RolGrant();
										grant.setDispatcher(getCodi());
										grant.setRolName(grantedRole);
										grant.setOwnerAccountName(accountName);
										grant.setOwnerDispatcher(getCodi());
										grants.add(grant);
									}
									found = true;
								}

							}
						}
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}

	private boolean tryGrantFetch(String accountName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT))
				{
					found = true;
					
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setOwnerAccountName(accountName);
					rg.setOwnerDispatcher(accountName);
					GrantExtensibleObject geo = new GrantExtensibleObject(rg, getServer());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject jsonObj = objectTranslator.generateObject(geo, mapping);
						if (jsonObj != null)
						{
							ExtensibleObjects jsonStoredObjects = searchJsonObjects(jsonObj);
							if (jsonStoredObjects != null)
							{
								for (ExtensibleObject jsonObject: jsonStoredObjects.getObjects())
								{
									
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
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
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(mapping.getSystemObject());
					
					ExtensibleObjects objects = loadJsonObjects(eo);
					
					if (objects == null)
						throw new InternalErrorException("No accounts found");
					for ( ExtensibleObject object : objects.getObjects())
					{
						String name = vom.toSingleString(objectTranslator.parseInputAttribute("accountName", object, mapping));
						if (name != null)
						{
							accounts.add(name);
						}
					}
				}
			}
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		} catch (UnsupportedEncodingException e) {
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
						ExtensibleObject jsonObj = objectTranslator.generateObject(new RoleExtensibleObject(role, getServer()), mapping);
						if (jsonObj != null)
						{
							ExtensibleObject jsonStoredObject = searchJsonObject(jsonObj);
							if (jsonStoredObject != null)
							{
								role  = vom.parseRol(objectTranslator.parseInputObject(jsonStoredObject, mapping));
								if (role != null)
									return role;
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
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(mapping.getSystemObject());
					
					ExtensibleObjects objects = loadJsonObjects(eo);
					
					for ( ExtensibleObject object : objects.getObjects())
					{
						String name = vom.toSingleString(objectTranslator.parseInputAttribute("name", object, mapping));
						if (name != null)
						{
							accounts.add(name);
						}
					}
				}
			}
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		} catch (UnsupportedEncodingException e) {
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
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					if (objectTranslator.evalCondition(object, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(object, mapping);
		    			if (obj != null)
		    				updateObject(object, obj);
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

	public boolean validateUserPassword(String arg0, Password arg1)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> mapping)
			throws RemoteException, InternalErrorException {
		this.objectMappings = mapping;
		this.objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), mapping);
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			
			public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
				return searchJsonObject(pattern);
			}
		});
	}


	protected ExtensibleObject searchJsonObject (ExtensibleObject object) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		ExtensibleObjects objects = searchJsonObjects(object);
		if (objects != null && objects.getObjects().size() > 0)
		{
			if (objects.getObjects().size() > 1)
			{
				if (debugEnabled)
				{
					log.info("Search for "+object.getObjectType()+" object returned more than one result");
				}
				throw new InternalErrorException("Search for "+object.getObjectType()+" object returned more than one result");
			}
			return objects.getObjects().get(0);
		}
		return null;
	}

	private ExtensibleObjects searchJsonObjects (ExtensibleObject object) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		for (InvocationMethod m: getMethods(object.getObjectType(), "select"))
		{
			ExtensibleObjects objects = invoke (m, object);
			if (objects != null && objects.getObjects().size() > 0)
			{
				return objects;
			}
		}
		return null;
	}

	private ExtensibleObjects loadJsonObjects (ExtensibleObject object) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		for (InvocationMethod m: getMethods(object.getObjectType(), "load"))
		{
			ExtensibleObjects objects = invoke (m, object);
			if (objects != null && objects.getObjects().size() > 0)
			{
				return objects;
			}
		}
		return null;
	}

	protected ExtensibleObjects invoke(InvocationMethod m, ExtensibleObject object) throws InternalErrorException, JSONException {

		String path = translatePath (m, object);
		
		ClientResponse response;
		if ( "GET".equalsIgnoreCase(m.method)) {
			if (m.encoding == null)
				m.encoding = MediaType.APPLICATION_FORM_URLENCODED;
			String params = encode(m, object);
			if (params != null && ! params.isEmpty())
				path = path +"?"+params;
			if (debugEnabled)
				log.info("Invoking GET on "+path);
			response = client.resource(path)
					.accept(MediaType.APPLICATION_JSON)
					.get();
		} else if ( "post".equalsIgnoreCase(m.method)) {
			if (m.encoding == null)
				m.encoding = MediaType.APPLICATION_FORM_URLENCODED;
			String params = encode(m, object);
			
			if (debugEnabled)
				log.info("Invoking POST on "+path+": "+params);
			
			response = client.resource(path)
					.contentType(MediaType.valueOf(m.encoding))
					.accept(MediaType.APPLICATION_JSON)
					.post(params);
		} else if ( "put".equalsIgnoreCase(m.method))  {
			if (m.encoding == null)
				m.method = MediaType.APPLICATION_FORM_URLENCODED;
			String params = encode(m, object);

			if (debugEnabled)
				log.info("Invoking PUT on "+path+": "+params);

			response = client.resource(path)
					.contentType(m.encoding)
					.accept(MediaType.APPLICATION_JSON)
					.put(params);
		} else if ( "delete".equalsIgnoreCase(m.method)) {
			if (m.encoding == null)
				m.method = MediaType.APPLICATION_FORM_URLENCODED;
			String params = encode(m, object);
			if (params != null && ! params.isEmpty())
				path = path +"?"+params;

			if (debugEnabled)
				log.info("Invoking DELETE on "+path);
			
			response = client.resource(path)
					.accept(MediaType.APPLICATION_JSON)
					.delete();
		} else 
			throw new InternalErrorException("Unknown method "+m.method);
 
		
		if (response.getStatusCode() == HttpStatus.NOT_FOUND.getCode())
		{
			response.consumeContent();
			return null;
		}
		if (response.getStatusCode() != HttpStatus.OK.getCode() &&
				response.getStatusCode() != HttpStatus.CREATED.getCode())
		{
			response.consumeContent();
			throw new RuntimeException("Error on invocation "+response.getMessage());
		}

		String txt = response.getEntity(String.class);
		ExtensibleObject resp = new ExtensibleObject();
		resp.setObjectType(object.getObjectType());
		if (txt.startsWith("{"))
		{
			JSONObject respOb  = new JSONObject(txt);
			Map<String, Object> map = new HashMap<String, Object>();
			json2map(respOb, map );
			resp.putAll(map);
		} else if (txt.startsWith("[")) {
			JSONArray respOb  = new JSONArray(txt);
			Map<String, Object> map = new HashMap<String, Object>();
			map.put("result", json2java(respOb));
			resp.putAll(map);
			if (m.results == null) 
				m.results = "result";
		} else {
			throw new InternalErrorException("Expecting JSON object from "+path+". Received:\n"+txt);
		}
		
		if (debugEnabled)
		{
			debugObject("Received from "+path, resp, "  ");
		}
		
		if (m.check != null && !m.check.isEmpty())
		{
			objectTranslator.eval(m.check, resp);
		}
	
		if (m.results != null)
		{
			ExtensibleObjects eos = new ExtensibleObjects();
			if (debugEnabled)
				log.info("Parsing results");
			Object result = objectTranslator.eval(m.results, resp);
			if (result instanceof Collection)
			{
				for (Object o: ((Collection) result))
				{
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(object.getObjectType());
					if (o instanceof Map)
						eo.putAll((Map<? extends String, ? extends Object>) o);
					else
						eo.put("result", o);
					if (debugEnabled)
						debugObject("Parsod object:", eo, "  ");
					eos.getObjects().add(eo);
				}
			}
			else
			{
				ExtensibleObject eo = new ExtensibleObject();
				eo.setObjectType(object.getObjectType());
				if (debugEnabled)
					debugObject("Parsod object:", eo, "  ");
				eos.getObjects().add(eo);
			}
			return eos;
		}
		else
		{
			ExtensibleObjects eos = new ExtensibleObjects();
			eos.getObjects().add(resp);
			return eos;
		}
	}

	private String translatePath(InvocationMethod m, ExtensibleObject object) throws InternalErrorException {
		int i = 0;
		String path = m.path;
		while ( i < path.length() && ( i = path.indexOf("${", i)) >= 0)
		{
			int j = path.indexOf("}", i);
			if (j < 0)
			{
				break;
			}
			String expr = path.substring(i+2, j);
			String result = vom.toSingleString(objectTranslator.eval(expr, object));
			if (result == null)
				result = "";
			try {
				path = path.substring(0, i) + URLEncoder.encode(result, "UTF-8") + path.substring(j+1);
			} catch (UnsupportedEncodingException e) {
			}
			i++;
		}
		return serverUrl+path;
	}

	private String encode(InvocationMethod m, ExtensibleObject object) throws JSONException, InternalErrorException {
		if ("application/x-www-form-urlencoded".equalsIgnoreCase(m.encoding) ||
				"multipart/form-data".equalsIgnoreCase(m.encoding))
		{
			StringBuffer sb = new StringBuffer();
			if ( m.parameters == null )
			{
				for (String att: object.getAttributes())
				{
					if (object.getAttribute(att) != null)
					{
						sb.append(URLEncoder.encode(att))
							.append("=")
							.append(URLEncoder.encode(object.getAttribute(att).toString()));
					}
				}
			} else {
				for (String att: m.parameters)
				{
					if (object.getAttribute(att) != null)
					{
						sb.append(URLEncoder.encode(att))
							.append("=")
							.append(URLEncoder.encode(object.getAttribute(att).toString()));
					}
				}
			}
			return sb.toString();
		}
		else if  ( MediaType.APPLICATION_JSON.equalsIgnoreCase(m.encoding) )
		{
			HashMap<String, Object> hm = new HashMap<String, Object>();
			if ( m.parameters == null )
			{
				for (String att: object.getAttributes())
				{
					if (object.getAttribute(att) != null)
					{
						hm.put(att, object.getAttribute(att));
					}
				}
			} else {
				for (String att: m.parameters)
				{
					if (object.getAttribute(att) != null)
					{
						hm.put(att, object.getAttribute(att));
					}
				}
			}
			return java2json(hm).toString();
		} else {
			throw new InternalErrorException("Encoding no soportado: "+m.encoding);
		}
	}

	private String getJsonReference(AttributeReference ar) {
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

	private void json2map(JSONObject jsonObject, Map<String,Object> map) throws JSONException 
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

	private void map2json(Map<String,Object> map, JSONObject jsonObject) throws JSONException 
	{
		for ( Iterator it = map.keySet().iterator(); it.hasNext(); )
		{
			String key = (String) it.next();
			Object value = map.get(key);
			jsonObject.put(key, java2json(value));
		}
		
	}

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

	protected List<InvocationMethod> getMethods(String objectType, String phase) throws InternalErrorException {
		ExtensibleObjectMapping mapping = getMapping(objectType);
		Map<String, InvocationMethod> map = new HashMap<String, InvocationMethod>();
		
		for (String k: mapping.getProperties().keySet() )
		{
			if (k.startsWith(phase))
			{
				String tag = k.substring(phase.length());
				String number = "";
				while (! tag.isEmpty() && Character.isDigit(tag.charAt(0)))
				{
					number = number + tag.charAt(0);
					tag = tag.substring(1);
				}
				
				InvocationMethod im = map.get(number);
				if ( im == null)
				{
					im = new InvocationMethod();
					map.put(number, im);
					im.name = number;
				}
				if (tag.equalsIgnoreCase("Path"))
					im.path = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Results"))
					im.results = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Check"))
					im.check = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Method"))
					im.method = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Encoding"))
					im.encoding = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Params"))
					im.parameters = mapping.getProperties().get(k).split("[, ]+");
				else
					throw new InternalErrorException("Unexpected property "+k+" for object type "+objectType);
			}
		}
		List<InvocationMethod> methods = new LinkedList<InvocationMethod>(map.values());
		Collections.sort(methods, new Comparator<InvocationMethod>() {
			public int compare(InvocationMethod o1, InvocationMethod o2) {
				return o1.name.compareTo(o2.name);
			}
		});
		
		if (methods.size() == 0)
			log.info("Notice: No properties found for method "+phase);
		return methods;
	}

	protected void updateObject (ExtensibleObject soffidobject, ExtensibleObject targetObject)
			throws InternalErrorException
	{
		try
		{
			ExtensibleObject existingObject = searchJsonObject(targetObject);
		
			if (existingObject == null)
			{
				for (InvocationMethod m: getMethods(targetObject.getObjectType(), "insert"))
				{
					if (runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidobject, targetObject, existingObject))
					{
						invoke (m, targetObject);
						runTrigger(SoffidObjectTrigger.POST_INSERT, soffidobject, targetObject, existingObject);
					}
				}
			}
			else
			{
				for (InvocationMethod m: getMethods(targetObject.getObjectType(), "update"))
				{
					if (runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidobject, targetObject, existingObject))
					{
						invoke (m, targetObject);
						runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidobject, targetObject, existingObject);
					}
				}
			}
		}
		catch (Exception e)
		{
			String msg = "updating object : " + targetObject.toString();
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
	}

	private ExtensibleObjectMapping getMapping(String objectType) {
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

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject newObject,
			ExtensibleObject oldObject) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (oldObject == null || oldObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", newObject);
						eo.setAttribute("oldObject", oldObject);
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

	public ExtensibleObject getNativeObject(com.soffid.iam.api.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public ExtensibleObject getSoffidObject(com.soffid.iam.api.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

}
	