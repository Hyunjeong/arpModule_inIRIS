package etri.sdn.controller.module.arpcontrol;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.omg.CORBA.PRIVATE_MEMBER;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;

import etri.sdn.controller.MessageContext;
import etri.sdn.controller.OFMFilter;
import etri.sdn.controller.OFModel;
import etri.sdn.controller.OFModule;
import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;
import etri.sdn.controller.util.Logger;

/**
 * MAC Learning Module. 
 * Modified the original LearningMac class of Floodlight.
 * 
 * @author bjlee
 *
 */
public final class OFMArpControl extends OFModule {

	
	// flow-mod - for use in the cookie
	private static final int LEARNING_SWITCH_APP_ID = 1;
	private static final int APP_ID_BITS = 12;
	private static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
	private static final long LEARNING_SWITCH_COOKIE = (long) (LEARNING_SWITCH_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

	private static final short IDLE_TIMEOUT_DEFAULT = 5;
	private static final short HARD_TIMEOUT_DEFAULT = 0;
	private static final short PRIORITY_DEFAULT = 100;
	// normally, setup reverse flow as well. 
	private static final boolean LEARNING_SWITCH_REVERSE_FLOW = true;
	private static final int MAX_MACS_PER_SWITCH  = 1000; 
	
	
	private Map<String, Object> arptable = new HashMap<String, Object>();

	/**
	 * Constructor to create learning mac module instance. 
	 * It does nothing internally.
	 */
	public OFMArpControl() {
		// does nothing
	}

	

	/**
	 * Writes a OFFlowMod to a switch.
	 * @param sw The switch tow rite the flowmod to.
	 * @param command The FlowMod actions (add, delete, etc).
	 * @param bufferId The buffer ID if the switch has buffered the packet.
	 * @param match The OFMatch structure to write.
	 * @param outPort The switch port to output it to.
	 */
	private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
			OFMatch match, short outPort, List<OFMessage> out) {
		// from openflow 1.0 spec - need to set these on a struct ofp_flow_mod:
		// struct ofp_flow_mod {
		//    struct ofp_header header;
		//    struct ofp_match match; /* Fields to match */
		//    uint64_t cookie; /* Opaque controller-issued identifier. */
		//
		//    /* Flow actions. */
		//    uint16_t command; /* One of OFPFC_*. */
		//    uint16_t idle_timeout; /* Idle time before discarding (seconds). */
		//    uint16_t hard_timeout; /* Max time before discarding (seconds). */
		//    uint16_t priority; /* Priority level of flow entry. */
		//    uint32_t buffer_id; /* Buffered packet to apply to (or -1).
		//                           Not meaningful for OFPFC_DELETE*. */
		//    uint16_t out_port; /* For OFPFC_DELETE* commands, require
		//                          matching entries to include this as an
		//                          output port. A value of OFPP_NONE
		//                          indicates no restriction. */
		//    uint16_t flags; /* One of OFPFF_*. */
		//    struct ofp_action_header actions[0]; /* The action length is inferred
		//                                            from the length field in the
		//                                            header. */
		//    };

		OFFlowMod flowMod = (OFFlowMod) sw.getConnection().getFactory().getMessage(OFType.FLOW_MOD);
		flowMod.setMatch(match);
		flowMod.setCookie(LEARNING_SWITCH_COOKIE);
		flowMod.setCommand(command);
		flowMod.setIdleTimeout(IDLE_TIMEOUT_DEFAULT);
		flowMod.setHardTimeout(HARD_TIMEOUT_DEFAULT);
		flowMod.setPriority(PRIORITY_DEFAULT);
		flowMod.setBufferId(bufferId);
		flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort : OFPort.OFPP_NONE.getValue());
		flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0 : (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

		// set the ofp_action_header/out actions:
		// from the openflow 1.0 spec: need to set these on a struct ofp_action_output:
		// uint16_t type; /* OFPAT_OUTPUT. */
		// uint16_t len; /* Length is 8. */
		// uint16_t port; /* Output port. */
		// uint16_t max_len; /* Max length to send to controller. */
		// type/len are set because it is OFActionOutput,
		// and port, max_len are arguments to this constructor
		flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort, (short) 0xffff)));
		flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

		// TODO: support for counter store.
		//		counterStore.updatePktOutFMCounterStore(sw, flowMod);

		// and write it out
		out.add(flowMod);
	}

	/**
	 * Writes an OFPacketOut message to a switch.
	 * 
	 * @param sw 				The switch to write the PacketOut to.
	 * @param packetInMessage 	The corresponding PacketIn.
	 * @param egressPort 		The switchport to output the PacketOut.
	 */
	private void writePacketOutForPacketIn(IOFSwitch sw, 
			OFPacketIn packetInMessage, 
			short egressPort,
			List<OFMessage> out) {
		// from openflow 1.0 spec - need to set these on a struct ofp_packet_out:
		// uint32_t buffer_id; /* ID assigned by datapath (-1 if none). */
		// uint16_t in_port; /* Packet's input port (OFPP_NONE if none). */
		// uint16_t actions_len; /* Size of action array in bytes. */
		// struct ofp_action_header actions[0]; /* Actions. */
		/* uint8_t data[0]; */ /* Packet data. The length is inferred
                                  from the length field in the header.
                                  (Only meaningful if buffer_id == -1.) */

		OFPacketOut packetOutMessage = (OFPacketOut) sw.getConnection().getFactory().getMessage(OFType.PACKET_OUT);
		short packetOutLength = (short)OFPacketOut.MINIMUM_LENGTH; // starting length

		// Set buffer_id, in_port, actions_len
		packetOutMessage.setBufferId(packetInMessage.getBufferId());
		packetOutMessage.setInPort(packetInMessage.getInPort());
		packetOutMessage.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
		packetOutLength += OFActionOutput.MINIMUM_LENGTH;

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>(1);      
		actions.add(new OFActionOutput(egressPort, (short) 0));
		packetOutMessage.setActions(actions);

		// set data - only if buffer_id == -1
		if (packetInMessage.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = packetInMessage.getPacketData();
			packetOutMessage.setPacketData(packetData); 
			packetOutLength += (short)packetData.length;
		}

		// finally, set the total length
		packetOutMessage.setLength(packetOutLength);              

		// TODO: counter store support
		//		counterStore.updatePktOutFMCounterStore(sw, packetOutMessage);
		out.add(packetOutMessage);
	}

	/**
	 * this method is a callback called by controller to request this module to 
	 * handle an incoming message. 
	 * 
	 * @param conn		connection that the message was received
	 * @param context	MessageContext object for the message.
	 * @param msg		the received message
	 * @param outgoing	list to put some outgoing messages to switch. 
	 */
	@Override
	public boolean handleMessage(Connection conn, MessageContext context, OFMessage msg, List<OFMessage> outgoing) {
		return processPacketInMessage(conn, context, msg, outgoing);
	}
	
	/**
	 * Handle disconnection to a switch. 
	 * As this module does not handle the event, this method just return true.
	 * 
	 * @param conn		connection to a switch (just disconnected)
	 */
	@Override
	public boolean handleDisconnect(Connection conn) {
		// does nothing currently.
		return true;
	}

	/**
	 * Processes a OFPacketIn message. If the switch has learned the MAC/VLAN to port mapping
	 * for the pair it will write a FlowMod for. If the mapping has not been learned the 
	 * we will flood the packet.
	 * 
	 * @param context 
	 * @param sw
	 * @param pi
	 * @return
	 */
	private boolean processPacketInMessage(Connection conn, MessageContext context, OFMessage msg, List<OFMessage> out) {
		
		if ( conn.getSwitch() == null ) {
			Logger.stderr("Connection is not fully handshaked");
			return true;
		}
		
		if ( msg == null ) {
			// this is critical. 
			// no further processing of this msg is possible.
			return false;
		}

		OFPacketIn pi = (OFPacketIn) msg;

		// Read in packet data headers by using OFMatch
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());		
		
		/**
		 * Process a ARP packet. Extraction MAC and IP address to store hashmap
		 */
		
		String sMAC = null, dMAC = null, sourceIP = null, destIP = null;
			
		
		if(match.getDataLayerType() == 0x0806){
			
//			Logger.stdout("ARP 맞다!!");
						
			sMAC = HexString.toHexString(match.getDataLayerSource());
			dMAC = HexString.toHexString(match.getDataLayerDestination());
			
			sourceIP = OFMatch.ipToString(match.getNetworkSource());
			destIP = OFMatch.ipToString(match.getNetworkDestination());
			
//			Logger.stdout("sourceMAC: " +sMAC+", destMAC: "+dMAC);
//			Logger.stdout("sourceIP: "+sourceIP+", destIP: "+destIP);		
		}
		
		arptable.put(sMAC, sourceIP);
//		arptable.put(dMAC, destIP);

		if(arptable.containsValue(destIP)){
			System.out.println(dMAC);
		}
			else{
				System.out.println("ARP reply 필요");
			}
				
		return false;
	}
									

	/**
	 * Initialize this module. As this module processes all PACKET_IN messages,
	 * it registers filter to receive those messages.
	 */
	@Override
	protected void initialize() {	
		registerFilter(
				OFType.PACKET_IN,
				new OFMFilter() {
					@Override
					public boolean filter(OFMessage m) {
						return true;
					}
				}
		);
	}

	/**
	 * As this module does not process handshake event, 
	 * it just returns true.
	 * 
	 * @return		true
	 */
	@Override
	protected boolean handleHandshakedEvent(Connection sw, MessageContext context) {
		return true;
	}

	/**
	 * As this module have no model, it just returns null
	 * 
	 * @return		null
	 */
	@Override
	public OFModel[] getModels() {
		// TODO Auto-generated method stub
		return null;
	}
}
