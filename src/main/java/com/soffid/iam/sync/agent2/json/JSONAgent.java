package com.soffid.iam.sync.agent2.json;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;

import org.json.JSONException;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.agent.json.InvocationMethod;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class JSONAgent extends com.soffid.iam.sync.agent.json.JSONAgent 
	implements CustomObjectMgr
{

	public JSONAgent() throws RemoteException {
	}


	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.appliesToSoffidObject(sourceObject))
				{
					ExtensibleObject target = objectTranslator.generateObject(sourceObject, map, true);
					ExtensibleObject target2 = searchJsonObject(target);
					return target2;						
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
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

	boolean moreData = false;
	String nextChange = null;
	@SuppressWarnings("unchecked")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM) ||
						mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE) ||
						mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP)
						)
				{
					for (InvocationMethod m: getMethods(mapping.getSystemObject(), "select"))
					{
						ExtensibleObject object = new ExtensibleObject();
						object.setObjectType(mapping.getSystemObject().toString());
						ExtensibleObjects objects = invoke (m, object);
						if (objects != null)
						{
							for (ExtensibleObject eo: objects.getObjects())
							{
								ExtensibleObject soffidUser = objectTranslator.parseInputObject(eo, mapping);
								AuthoritativeChange ch = vom.parseAuthoritativeChange(soffidUser);
								if (ch != null)
									changes.add(ch);
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
}
