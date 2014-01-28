package etri.sdn.controller.module.hub;

import java.util.List;

import org.openflow.protocol.OFMessage;

import etri.sdn.controller.MessageContext;
import etri.sdn.controller.OFModel;
import etri.sdn.controller.OFModule;
import etri.sdn.controller.protocol.io.Connection;

public class Hub extends OFModule {

	@Override
	protected void initialize() {
		registerModule(IHubService.class, this);

	}

	@Override
	protected boolean handleHandshakedEvent(Connection conn,
			MessageContext context) {
		return true;
	}

	@Override
	protected boolean handleMessage(Connection conn, MessageContext context,
			OFMessage msg, List<OFMessage> outgoing) {
		// TODO:
		return true;
	}
	
	@Override
	protected boolean handleDisconnect(Connection conn) {
		return true;
	}

	@Override
	public OFModel[] getModels() {
		// TODO Auto-generated method stub
		return null;
	}

}
