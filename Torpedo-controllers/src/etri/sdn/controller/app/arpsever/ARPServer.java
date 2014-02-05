package etri.sdn.controller.app.arpsever;

import java.util.LinkedList;
import java.util.List;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;

import etri.sdn.controller.MessageContext;
import etri.sdn.controller.OFController;
import etri.sdn.controller.OFModule;
import etri.sdn.controller.module.arpcontrol.OFMArpControl;
import etri.sdn.controller.module.learningmac.OFMLearningMac;
import etri.sdn.controller.module.linkdiscovery.OFMLinkDiscovery;
import etri.sdn.controller.protocol.io.Connection;

public class ARPServer extends OFController{
	

	private OFMLinkDiscovery m_link_discovery = new OFMLinkDiscovery();
	private OFMArpControl m_arp_control = new OFMArpControl();
	
	private OFModule[] packet_in_pipeline = { 
			m_arp_control,
			m_link_discovery
	};
	
	public ARPServer(int num_of_queue, String role) {
		super(num_of_queue, role);
		// TODO Auto-generated constructor stub
	}

	@Override
	public void init() {
		// TODO Auto-generated method stub
		m_arp_control.init(this);
		m_link_discovery.init(this);
	}

	@Override
	public boolean handlePacketIn(Connection conn, MessageContext context,
			OFPacketIn pi) {
		// TODO Auto-generated method stub
		List<OFMessage> out = new LinkedList<OFMessage>();
		for ( int i = 0; i < packet_in_pipeline.length; ++i ) {
			boolean cont = packet_in_pipeline[i].processMessage( conn, context, pi, out );
			if ( !conn.write(out) ) {
				return false;
			}
			if ( !cont ) {
				// we process this packet no further.
				break;
			}
			out.clear();
		}
		return true;
	}

	@Override
	public boolean handleGeneric(Connection conn, MessageContext context,
			OFMessage m) {
		// TODO Auto-generated method stub
		if ( m.getType() == OFType.PORT_STATUS ) {
			List<OFMessage> out = new LinkedList<OFMessage>();

			m_link_discovery.processMessage( conn, context, m, out );
			if ( !conn.write(out) ) {
				// no further processing is possible.
				return true;
			}
		}
		else if ( m.getType() == OFType.FEATURES_REPLY ) {
			return m_link_discovery.processHandshakeFinished( conn, context );
		}
		else {
			System.err.println("Unhandled OF message: "
					+ m.getType() + " from "
					+ conn.getClient().socket().getInetAddress());
		}
		return true;
	}

}
