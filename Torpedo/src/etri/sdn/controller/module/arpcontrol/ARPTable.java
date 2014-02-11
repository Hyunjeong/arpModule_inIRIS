package etri.sdn.controller.module.arpcontrol;

import etri.sdn.controller.module.storage.IStorageService;
import etri.sdn.controller.module.storagemanager.OFMStorageManager;

public class ARPTable {

	private String sourcemac, destmac;
	private String sourceip, destip;
	
	public String getSourcemac() {
		return sourcemac;
	}

	public void setSourcemac(String sourcemac) {
		this.sourcemac = sourcemac;
	}

	public String getDestmac() {
		return destmac;
	}

	public void setDestmac(String destmac) {
		this.destmac = destmac;
	}

	public String getSourceip() {
		return sourceip;
	}

	public void setSourceip(String sourceip) {
		this.sourceip = sourceip;
	}

	public String getDestip() {
		return destip;
	}

	public void setDestip(String destip) {
		this.destip = destip;
	}
}
