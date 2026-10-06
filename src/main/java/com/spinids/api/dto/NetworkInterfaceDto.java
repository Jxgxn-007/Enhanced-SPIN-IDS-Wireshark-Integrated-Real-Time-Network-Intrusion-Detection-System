package com.spinids.api.dto;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Transfer Object representing a discovered network interface.
 */
public class NetworkInterfaceDto {

    private String name;
    private String displayName;
    private String description;
    private List<String> addresses = new ArrayList<>();
    private List<String> ipv4Addresses = new ArrayList<>();
    private List<String> ipv6Addresses = new ArrayList<>();
    private String macAddress;
    private boolean loopback;
    private boolean up;
    private boolean recommended;

    public NetworkInterfaceDto() {}

    public NetworkInterfaceDto(String name, String displayName, String description,
                               List<String> addresses, List<String> ipv4Addresses,
                               List<String> ipv6Addresses, String macAddress,
                               boolean loopback, boolean up, boolean recommended) {
        this.name = name;
        this.displayName = displayName;
        this.description = description;
        this.addresses = addresses != null ? addresses : new ArrayList<>();
        this.ipv4Addresses = ipv4Addresses != null ? ipv4Addresses : new ArrayList<>();
        this.ipv6Addresses = ipv6Addresses != null ? ipv6Addresses : new ArrayList<>();
        this.macAddress = macAddress;
        this.loopback = loopback;
        this.up = up;
        this.recommended = recommended;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<String> addresses) {
        this.addresses = addresses;
    }

    public List<String> getIpv4Addresses() {
        return ipv4Addresses;
    }

    public void setIpv4Addresses(List<String> ipv4Addresses) {
        this.ipv4Addresses = ipv4Addresses;
    }

    public List<String> getIpv6Addresses() {
        return ipv6Addresses;
    }

    public void setIpv6Addresses(List<String> ipv6Addresses) {
        this.ipv6Addresses = ipv6Addresses;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public boolean isLoopback() {
        return loopback;
    }

    public void setLoopback(boolean loopback) {
        this.loopback = loopback;
    }

    public boolean isUp() {
        return up;
    }

    public void setUp(boolean up) {
        this.up = up;
    }

    public boolean isRecommended() {
        return recommended;
    }

    public void setRecommended(boolean recommended) {
        this.recommended = recommended;
    }
}
