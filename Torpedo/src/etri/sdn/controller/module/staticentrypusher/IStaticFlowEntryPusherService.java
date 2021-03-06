package etri.sdn.controller.module.staticentrypusher;

import java.util.Map;

import org.openflow.protocol.OFFlowMod;

import etri.sdn.controller.IService;

/**
 * This interface represents a service that the implementation of interface 
 * provides to other IRIS modules. 
 * 
 * @author shkang
 *
 */
public interface IStaticFlowEntryPusherService extends IService {
    /**
     * Adds a static flow.
     * 
     * @param name 		Name of the flow mod. Must be unique.
     * @param fm		The flow to push.
     * @param swDpid 	The switch DPID to push it to, in 00:00:00:00:00:00:00:01 notation.
     */
    public void addFlow(String name, OFFlowMod fm, String swDpid);
    
    /**
     * Deletes a static flow
     * 
     * @param name The name of the static flow to delete.
     */
    public boolean deleteFlow(String name);
    
    /**
     * Deletes all static flows for a practicular switch
     * @param dpid The DPID of the switch to delete flows for.
     */
    public void deleteFlowsForSwitch(long dpid);
    
    /**
     * Deletes all flows.
     */
    public void deleteAllFlows();
    
    /**
     * Gets all list of all flows.
     * The first key is the DPID, and the second key is the name of flow-mod record
     * (for example, 'flow-mod-1').
     */
    public Map<String, Map<String, OFFlowMod>> getFlows();
    
    /**
     * Gets a list of flows by switch.
     * The first key is the name of flow-mod record (for example, 'flow-mod-1'). 
     */
    public Map<String, OFFlowMod> getFlows(String dpid);
}
