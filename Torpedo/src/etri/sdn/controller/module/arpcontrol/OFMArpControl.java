package etri.sdn.controller.module.arpcontrol;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
import org.openflow.util.LRULinkedHashMap;
import org.openflow.util.U8;

import etri.sdn.controller.MessageContext;
import etri.sdn.controller.OFMFilter;
import etri.sdn.controller.OFModel;
import etri.sdn.controller.OFModule;
import etri.sdn.controller.module.learningmac.MacVlanPair;
import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;
import etri.sdn.controller.protocol.packet.ARP;
import etri.sdn.controller.protocol.packet.Ethernet;
import etri.sdn.controller.util.Logger;

/**
 * ARP Table Managing Module. Modified the LearningMac class of IRIS.
 * 
 * @author hjCho, msLee
 * 
 */
public final class OFMArpControl extends OFModule {
	/**
	 * Table to save learning result.
	 */
	private Map<IOFSwitch, Map<MacVlanPair, Short>> macVlanToSwitchPortMap = new ConcurrentHashMap<IOFSwitch, Map<MacVlanPair, Short>>();

	// flow-mod - for use in the cookie
	private static final int LEARNING_SWITCH_APP_ID = 1;
	private static final int APP_ID_BITS = 12;
	private static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
	private static final long LEARNING_SWITCH_COOKIE = (long) (LEARNING_SWITCH_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

	private static final short IDLE_TIMEOUT_DEFAULT = 50;
	private static final short HARD_TIMEOUT_DEFAULT = 0;
	private static final short PRIORITY_DEFAULT = 100;
	// normally, setup reverse flow as well.
	private static final boolean LEARNING_SWITCH_REVERSE_FLOW = true;

	private static final int MAX_MACS_PER_SWITCH = 1000;

	public static Map<String, Object> arptable = new HashMap<String, Object>();

	
	@Override
	protected void initialize() {
		registerFilter(OFType.PACKET_IN, new OFMFilter() {
			@Override
			public boolean filter(OFMessage m) {
				return true;
			}
		});
	}

	@Override
	protected boolean handleHandshakedEvent(Connection conn,
			MessageContext context) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	protected boolean handleMessage(Connection conn, MessageContext context,
			OFMessage msg, List<OFMessage> outgoing) {
		return processPacketInMessage(conn, context, msg, outgoing);
	}

	private void addToARPTable(String IP, String MAC) {
		arptable.put(IP, MAC);
	}

	private String lookupARPTable(String destinationIP) {
		if (arptable.containsKey(destinationIP)) {
			String destMAC = (String) arptable.get(destinationIP);
			return destMAC;
		} else
			return "";
	}

	/**
	 * Writes an OFPacketOut message to a switch.
	 * 
	 * @param sw
	 *            The switch to write the PacketOut to.
	 * @param packetInMessage
	 *            The corresponding PacketIn.
	 * @param egressPort
	 *            The switchport to output the PacketOut.
	 */
	private void writePacketOutForPacketIn(IOFSwitch sw,
			OFPacketIn packetInMessage, short egressPort, List<OFMessage> out) {
		// from openflow 1.0 spec - need to set these on a struct
		// ofp_packet_out:
		// uint32_t buffer_id; /* ID assigned by datapath (-1 if none). */
		// uint16_t in_port; /* Packet's input port (OFPP_NONE if none). */
		// uint16_t actions_len; /* Size of action array in bytes. */
		// struct ofp_action_header actions[0]; /* Actions. */
		/* uint8_t data[0]; *//*
							 * Packet data. The length is inferred from the
							 * length field in the header. (Only meaningful if
							 * buffer_id == -1.)
							 */

		OFPacketOut packetOutMessage = (OFPacketOut) sw.getConnection()
				.getFactory().getMessage(OFType.PACKET_OUT);
		short packetOutLength = (short) OFPacketOut.MINIMUM_LENGTH; // starting
		// length

		// Set buffer_id, in_port, actions_len
		packetOutMessage.setBufferId(packetInMessage.getBufferId());
		packetOutMessage.setInPort(packetInMessage.getInPort());
		packetOutMessage
				.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		packetOutLength += OFActionOutput.MINIMUM_LENGTH;

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>(1);
		actions.add(new OFActionOutput(egressPort, (short) 0));
		packetOutMessage.setActions(actions);

		// set data - only if buffer_id == -1
		// packetIn의 데이터를 packetOut의 데이터로!!! buffer_id = -1 이 의미하는 바가 뭐지?
		// if (packetInMessage.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
		byte[] packetData = packetInMessage.getPacketData();
		packetOutMessage.setPacketData(packetData);
		packetOutLength += (short) packetData.length;
		// }

		// finally, set the total length
		packetOutMessage.setLength(packetOutLength);

		// TODO: counter store support
		// counterStore.updatePktOutFMCounterStore(sw, packetOutMessage);
		out.add(packetOutMessage);
		Logger.stdout("Packet out data : "
				+ HexString.toHexString(packetOutMessage.getPacketData()));
	}

	/**
	 * Adds a host to the MAC/VLAN->SwitchPort mapping
	 * 
	 * @param sw
	 *            The switch to add the mapping to
	 * @param mac
	 *            The MAC address of the host to add
	 * @param vlan
	 *            The VLAN that the host is on
	 * @param portVal
	 *            The switchport that the host is on
	 */
	protected void addToPortMap(IOFSwitch sw, long mac, short vlan,
			short portVal) {
		Map<MacVlanPair, Short> swMap = macVlanToSwitchPortMap.get(sw);

		if (vlan == (short) 0xffff) {
			// OFMatch.loadFromPacket sets VLAN ID to 0xffff if the packet
			// contains no VLAN tag;
			// for our purposes that is equivalent to the default VLAN ID 0
			vlan = 0;
		}

		if (swMap == null) {
			// May be accessed by REST API so we need to make it thread safe
			// swMap = new ConcurrentHashMap<MacVlanPair,Short>();
			swMap = Collections
					.synchronizedMap(new LRULinkedHashMap<MacVlanPair, Short>(
							MAX_MACS_PER_SWITCH));
			macVlanToSwitchPortMap.put(sw, swMap);
		}
		swMap.put(new MacVlanPair(mac, vlan, sw), portVal);
	}

	/**
	 * Get the port that a MAC/VLAN pair is associated with
	 * 
	 * @param sw
	 *            The switch to get the mapping from
	 * @param mac
	 *            The MAC address to get
	 * @param vlan
	 *            The VLAN number to get
	 * @return The port the host is on
	 */
	public Short getFromPortMap(IOFSwitch sw, long mac, short vlan) {
		if (vlan == (short) 0xffff) {
			vlan = 0;
		}

		Map<MacVlanPair, Short> swMap = macVlanToSwitchPortMap.get(sw);
		if (swMap != null)
			return swMap.get(new MacVlanPair(mac, vlan, sw));

		// if none found
		return null;
	}

	/**
	 * Writes a OFFlowMod to a switch.
	 * 
	 * @param sw
	 *            The switch tow rite the flowmod to.
	 * @param command
	 *            The FlowMod actions (add, delete, etc).
	 * @param bufferId
	 *            The buffer ID if the switch has buffered the packet.
	 * @param match
	 *            The OFMatch structure to write.
	 * @param outPort
	 *            The switch port to output it to.
	 */
	private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
			OFMatch match, short outPort, List<OFMessage> out) {
		// from openflow 1.0 spec - need to set these on a struct ofp_flow_mod:
		// struct ofp_flow_mod {
		// struct ofp_header header;
		// struct ofp_match match; /* Fields to match */
		// uint64_t cookie; /* Opaque controller-issued identifier. */
		//
		// /* Flow actions. */
		// uint16_t command; /* One of OFPFC_*. */
		// uint16_t idle_timeout; /* Idle time before discarding (seconds). */
		// uint16_t hard_timeout; /* Max time before discarding (seconds). */
		// uint16_t priority; /* Priority level of flow entry. */
		// uint32_t buffer_id; /* Buffered packet to apply to (or -1).
		// Not meaningful for OFPFC_DELETE*. */
		// uint16_t out_port; /* For OFPFC_DELETE* commands, require
		// matching entries to include this as an
		// output port. A value of OFPP_NONE
		// indicates no restriction. */
		// uint16_t flags; /* One of OFPFF_*. */
		// struct ofp_action_header actions[0]; /* The action length is inferred
		// from the length field in the
		// header. */
		// };

		OFFlowMod flowMod = (OFFlowMod) sw.getConnection().getFactory()
				.getMessage(OFType.FLOW_MOD);
		flowMod.setMatch(match);
		flowMod.setCookie(LEARNING_SWITCH_COOKIE);
		flowMod.setCommand(command);
		flowMod.setIdleTimeout(IDLE_TIMEOUT_DEFAULT);
		flowMod.setHardTimeout(HARD_TIMEOUT_DEFAULT);
		flowMod.setPriority(PRIORITY_DEFAULT);
		flowMod.setBufferId(bufferId);
		flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort
				: OFPort.OFPP_NONE.getValue());
		flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0
				: (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

		// set the ofp_action_header/out actions:
		// from the openflow 1.0 spec: need to set these on a struct
		// ofp_action_output:
		// uint16_t type; /* OFPAT_OUTPUT. */
		// uint16_t len; /* Length is 8. */
		// uint16_t port; /* Output port. */
		// uint16_t max_len; /* Max length to send to controller. */
		// type/len are set because it is OFActionOutput,
		// and port, max_len are arguments to this constructor
		flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort,
				(short) 0xffff)));
		flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

		// TODO: support for counter store.
		// counterStore.updatePktOutFMCounterStore(sw, flowMod);

		// and write it out
		out.add(flowMod);
	}

	public boolean processPacketInMessage(Connection conn,
			MessageContext context, OFMessage msg, List<OFMessage> out) {

		if (conn.getSwitch() == null) {
			Logger.stderr("Connection is not fully handshaked");
			return true;
		}

		if (msg == null) {
			// this is critical.
			// no further processing of this msg is possible.
			return false;
		}

		OFPacketIn pi = (OFPacketIn) msg;
		byte[] packetData = pi.getPacketData();

		OFMatch match = new OFMatch();

		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		Long destMac = Ethernet.toLong(match.getDataLayerDestination());

		Short vlan = match.getDataLayerVirtualLan();

		// VLAN management packet
		if ((destMac & 0xfffffffffff0L) == 0x0180c2000000L) {
			return true;
		}

		if ((sourceMac & 0x010000000000L) == 0) {
			// If source MAC is a unicast address, learn the port for this
			// MAC/VLAN
			this.addToPortMap(conn.getSwitch(), sourceMac, vlan, pi.getInPort());
		}

		if (match.getDataLayerType() == 0x0806) {

			Logger.stdout("Packet in data : "
					+ HexString.toHexString(packetData));
			InetAddress addr = null;
			try {
				addr = InetAddress.getLocalHost();
			} catch (UnknownHostException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			NetworkInterface mac = null;
			try {
				mac = NetworkInterface.getByInetAddress(addr);
			} catch (SocketException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			byte[] controllerMAC = null;
			try {
				controllerMAC = mac.getHardwareAddress();
			} catch (SocketException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			System.out.println(HexString.toHexString(controllerMAC));

			byte[] sourceIP = Arrays.copyOfRange(packetData, 28, 32);
			byte[] destinationIP = Arrays.copyOfRange(packetData, 38, 42);
			byte[] sourceMAC = Arrays.copyOfRange(packetData, 6, 12);
			byte[] destinationMAC = Arrays.copyOfRange(packetData, 0, 6);
			short opCode = ByteBuffer.wrap(packetData, 20, 2).getShort();

			String str = "Before : \n"; // l2
			str += "\n1. Destination MAC : "
					+ HexString.toHexString(match.getDataLayerDestination());
			str += "\n2. Destination MAC : "
					+ HexString.toHexString(destinationMAC);

			str += "\n1.Source MAC : "
					+ HexString.toHexString(match.getDataLayerSource());
			str += "\n2.Source MAC : " + HexString.toHexString(sourceMAC);

			// l3
			if (match.getNetworkDestinationMaskLen() > 0)
				str += "\n1.Destination IP : "
						+ cidrToString(match.getNetworkDestination(),
								match.getNetworkDestinationMaskLen());
			str += "\n2.Destination IP : "
					+ HexString.toHexString(destinationIP);

			if (match.getNetworkSourceMaskLen() > 0)
				str += "\n1.Source IP : "
						+ cidrToString(match.getNetworkSource(),
								match.getNetworkSourceMaskLen());
			str += "\n2.Source IP : " + HexString.toHexString(sourceIP);
			Logger.stdout(str);

			Logger.stdout("\nopcode : " + opCode);
			// MAC & IP Address byte to String transform

			String sMAC = String.valueOf(HexString.toHexString(sourceMAC));
			String dMAC = String.valueOf(HexString.toHexString(destinationMAC));

			String sIP = cidrToString(match.getNetworkSource(),
					match.getNetworkSourceMaskLen());
			String dIP = cidrToString(match.getNetworkDestination(),
					match.getNetworkDestinationMaskLen());

			/*
			 * System.out.print("opcode : " + opCode);
			 * System.out.println(" /// " + (opCode == ARP.OP_REQUEST));
			 */

			ARP arpPacket = new ARP();
			arpPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
			arpPacket.setProtocolType(ARP.PROTO_TYPE_IP);
			arpPacket.setOpCode(opCode);
			arpPacket.setSenderHardwareAddress(sourceMAC);
			arpPacket.setSenderProtocolAddress(sourceIP);
			arpPacket.setTargetHardwareAddress(destinationMAC);
			arpPacket.setTargetProtocolAddress(destinationIP);

			/*
			 * System.out.println(sourceMAC.toString());
			 * System.out.println(HexString.toHexString(sourceMAC));
			 * System.out.println(HexString.toHexString(sourceMAC).toString());
			 * System.out.println("====");
			 */

			// normal ARP msg
			if (!arpPacket.isGratuitous()) {
				addToARPTable(sIP, sMAC); // *** Request든, Reply든 IP와 MAC을 저장한다

				System.out.println("\n*******" + arptable);
				System.out
						.println("=============================================");

				// normal ARP msg
				if (!arpPacket.isGratuitous()) {
					addToARPTable(sIP, sMAC); // *** Request든, Reply든 IP와 MAC을 저장한다
					System.out.println("\n*******" + arptable);

					// ARP request msg
					if (opCode == ARP.OP_REQUEST) {

						// ARP table lookup
						String findedDestinationMAC = lookupARPTable(dIP);

						// ARP table hit
						try {
							if (findedDestinationMAC != null
									&& !findedDestinationMAC.equals("")) {
								Logger.stdout("hit!!!!!!!!!\n");
								String[] sfindedDestinationMAC = findedDestinationMAC
										.split(":");
								byte[] bfindedDestinationMAC = HexString
										.fromHexString(findedDestinationMAC);
								// for(int i = 0; i <
								// sfindedDestinationMAC.length;
								// i++){
								// String tmp = sfindedDestinationMAC[i];
								// bfindedDestinationMAC[i] =
								// tmp.getBytes(charset)
								// }
								// arp reply 만들고
								System.arraycopy(sourceMAC, 0, packetData, 0,
										sourceMAC.length);
								System.arraycopy(sourceMAC, 0, packetData, 32,
										sourceMAC.length);
								System.arraycopy(bfindedDestinationMAC, 0,
										packetData, 6,
										bfindedDestinationMAC.length);
								System.arraycopy(bfindedDestinationMAC, 0,
										packetData, 22,
										bfindedDestinationMAC.length);
								System.arraycopy(sourceIP, 0, packetData, 38,
										sourceIP.length);
								System.arraycopy(destinationIP, 0, packetData,
										28, destinationIP.length);

								ByteBuffer buffer = ByteBuffer.allocate(2);
								buffer.putShort(ARP.OP_REPLY);
								buffer.flip();
								byte[] opCodeForReply = buffer.array();

								System.arraycopy(opCodeForReply, 0, packetData,
										20, opCodeForReply.length);


								match.setDataLayerDestination(bfindedDestinationMAC);
								match.setDataLayerSource(controllerMAC);

								Short outPort = getFromPortMap(
										conn.getSwitch(), destMac, vlan);

								// flow rule을 switch에 보내고

								if (outPort == null) {
									// If we haven't learned the port for the
									// dest MAC/VLAN, flood it
									// Don't flood broadcast packets if the
									// broadcast is disabled.
									// XXX For LearningSwitch this doesn't do
									// much. The sourceMac is removed
									// from port map whenever a flow expires, so
									// you would still see
									// a lot of floods.
									this.writePacketOutForPacketIn(
											conn.getSwitch(), pi,
											OFPort.OFPP_FLOOD.getValue(), out);
								} else if (outPort == match.getInputPort()) {

									match.setWildcards(((Integer) conn
											.getSwitch()
											.getAttribute(
													IOFSwitch.PROP_FASTWILDCARDS))
											.intValue()
											& ~OFMatch.OFPFW_IN_PORT
											& ~OFMatch.OFPFW_DL_VLAN
											& ~OFMatch.OFPFW_DL_SRC
											& ~OFMatch.OFPFW_DL_DST
											& ~OFMatch.OFPFW_NW_SRC_MASK
											& ~OFMatch.OFPFW_NW_DST_MASK);
									this.writeFlowMod(conn.getSwitch(),
											OFFlowMod.OFPFC_ADD,
											pi.getBufferId(), match, outPort,
											out);
								}

								// reply packet 전송

								this.writePacketOutForPacketIn(
										conn.getSwitch(), pi.setPacketData(packetData),
										OFPort.OFPP_FLOOD.getValue(), out);
								Logger.stdout("\nafter opcode : "
										+ HexString.toHexString(opCodeForReply));

							}
							// ARP table miss
							else {
								// request msg를 브로드캐스트
								this.writePacketOutForPacketIn(
										conn.getSwitch(), pi,
										OFPort.OFPP_FLOOD.getValue(), out);
							}
						}
						// catch(NullPointerException e)
						// {
						// System.out.println("Null point exception!!! ==> findedDestinationMAC : "
						// + findedDestinationMAC);
						// }
						catch (ArrayStoreException e) {
							System.out
									.println("array store exception!!! ==> findedDestinationMAC : "
											+ findedDestinationMAC);
							System.out.println(e);

						}
					}
					// ARP reply msg
					else if (opCode == ARP.OP_REPLY) {
						// flow rule switch에 전송

						Short outPort = getFromPortMap(conn.getSwitch(),
								destMac, vlan);
						System.out.println(match.getInputPort() + "    "
								+ outPort);

						match.setDataLayerSource(controllerMAC);

						match.setWildcards(((Integer) conn.getSwitch()
								.getAttribute(IOFSwitch.PROP_FASTWILDCARDS))
								.intValue()
								& ~OFMatch.OFPFW_IN_PORT
								& ~OFMatch.OFPFW_DL_VLAN
								& ~OFMatch.OFPFW_DL_SRC
								& ~OFMatch.OFPFW_DL_DST
								& ~OFMatch.OFPFW_NW_SRC_MASK
								& ~OFMatch.OFPFW_NW_DST_MASK);
						this.writeFlowMod(conn.getSwitch(),
								OFFlowMod.OFPFC_ADD, pi.getBufferId(), match,
								outPort, out);

						// reply msg 전달
					}
				}
				// gratuitous ARP msg
				else {
				}
			}
		}
		
//		// Now output flow-mod and/or packet
//				Short outPort = getFromPortMap(conn.getSwitch(), destMac, vlan);
//				if (outPort == null) {
//					// If we haven't learned the port for the dest MAC/VLAN, flood it
//					// Don't flood broadcast packets if the broadcast is disabled.
//					// XXX For LearningSwitch this doesn't do much. The sourceMac is removed
//					//     from port map whenever a flow expires, so you would still see
//					//     a lot of floods.
//					this.writePacketOutForPacketIn(conn.getSwitch(), pi, OFPort.OFPP_FLOOD.getValue(), out);
//				} else if (outPort == match.getInputPort()) {
//					// ignore this packet.
//					//            log.trace("ignoring packet that arrived on same port as learned destination:"
//					//                    + " switch {} vlan {} dest MAC {} port {}",
//					//                    new Object[]{ sw, vlan, HexString.toHexString(destMac), outPort });
//				} else {
//					// Add flow table entry matching source MAC, dest MAC, VLAN and input port
//					// that sends to the port we previously learned for the dest MAC/VLAN.  Also
//					// add a flow table entry with source and destination MACs reversed, and
//					// input and output ports reversed.  When either entry expires due to idle
//					// timeout, remove the other one.  This ensures that if a device moves to
//					// a different port, a constant stream of packets headed to the device at
//					// its former location does not keep the stale entry alive forever.
//					// FIXME: current HP switches ignore DL_SRC and DL_DST fields, so we have to match on
//					// NW_SRC and NW_DST as well
//					match.setWildcards(
//							((Integer)conn.getSwitch().getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
//							& ~OFMatch.OFPFW_IN_PORT
//							& ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
//							& ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK
//					);
//					this.writeFlowMod(conn.getSwitch(), OFFlowMod.OFPFC_ADD, pi.getBufferId(), match, outPort, out);
//					if (LEARNING_SWITCH_REVERSE_FLOW) {
//						this.writeFlowMod(conn.getSwitch(), OFFlowMod.OFPFC_ADD, -1, match.clone()
//								.setDataLayerSource(match.getDataLayerDestination())
//								.setDataLayerDestination(match.getDataLayerSource())
//								.setNetworkSource(match.getNetworkDestination())
//								.setNetworkDestination(match.getNetworkSource())
//								.setTransportSource(match.getTransportDestination())
//								.setTransportDestination(match.getTransportSource())
//								.setInputPort(outPort),
//								match.getInputPort(),
//								out
//						);
//					}
//				}

		return false;

	}

	public static String ipToString(int ip) {
		return Integer.toString(U8.f((byte) ((ip & 0xff000000) >> 24))) + "."
				+ Integer.toString((ip & 0x00ff0000) >> 16) + "."
				+ Integer.toString((ip & 0x0000ff00) >> 8) + "."
				+ Integer.toString(ip & 0x000000ff);
	}

	private String cidrToString(int ip, int prefix) {
		String str;
		if (prefix >= 32) {
			str = ipToString(ip);
		} else {
			// use the negation of mask to fake endian magic
			int mask = ~((1 << (32 - prefix)) - 1);
			str = ipToString(ip & mask) + "/" + prefix;
		}

		return str;
	}

	/**
	 * Initialize this module. As this module processes all PACKET_IN messages,
	 * it registers filter to receive those messages.
	 */

	@Override
	protected boolean handleDisconnect(Connection conn) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public OFModel[] getModels() {
		// TODO Auto-generated method stub
		return null;
	}

}
