package com.spinids.api.dto;

public class SelectInterfaceRequest {
    private String interfaceName;

    public SelectInterfaceRequest() {}

    public SelectInterfaceRequest(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public void setInterfaceName(String interfaceName) {
        this.interfaceName = interfaceName;
    }
}
