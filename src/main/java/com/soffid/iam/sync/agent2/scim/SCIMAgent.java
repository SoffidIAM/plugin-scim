package com.soffid.iam.sync.agent2.scim;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;

import javax.ws.rs.core.MediaType;

import org.apache.wink.client.ClientResponse;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReferenceParser;
import es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;

public class SCIMAgent extends com.soffid.iam.sync.agent.scim.SCIMAgent 
	implements CustomObjectMgr
{

	public SCIMAgent() throws RemoteException {
	}


	public ExtensibleObject getNativeObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.getSoffidObject().toString().equals(sourceObject.getObjectType()))
				{
					if (! type.equals(SoffidObjectType.OBJECT_CUSTOM) ||
							object1.equals(map.getSoffidCustomObject()))
					{
						ExtensibleObject target = objectTranslator.generateObject(sourceObject, map, true);
						ExtensibleObject target2 = searchJsonObject(target);
						return target2;						
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}

	public ExtensibleObject getSoffidObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.getSoffidObject().toString().equals(sourceObject.getObjectType()))
				{
					if (! type.equals(SoffidObjectType.OBJECT_CUSTOM) ||
							object1.equals(map.getSoffidCustomObject()))
					{
						ExtensibleObject target = objectTranslator.generateObject(sourceObject, map, true);
						ExtensibleObject target2 = searchJsonObject(target);
						ExtensibleObject src2 = objectTranslator.parseInputObject(target2, map);
						if (src2 != null)
							return src2;
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}


	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		try {
			CustomExtensibleObject sourceObject = new CustomExtensibleObject(obj, 
					getServer());
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.appliesToSoffidObject(sourceObject) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject target = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, target);
					}
					else
					{
						removeCustomObject(obj);
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


	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		CustomExtensibleObject sourceObject = new CustomExtensibleObject(obj, 
				getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject target = objectTranslator.generateObject(sourceObject, eom);
						if (obj != null)
							removeObject(sourceObject, target);
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

	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP) ||
						mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM))
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
}
