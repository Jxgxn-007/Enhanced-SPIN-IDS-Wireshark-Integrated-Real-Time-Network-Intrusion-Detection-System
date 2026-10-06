import { useState, useEffect, useCallback } from 'react';
import type { StatusResponse, SimulationRequest, SimulationResponse, NetworkInterfaceDto } from '../types/api';
import { api } from '../services/api';

export function useEngine() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceDto[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSimulation, setLastSimulation] = useState<SimulationResponse | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setError(null);
      const data = await api.getStatus();
      setStatus(data);
      if (data.selectedInterface) {
        setSelectedInterface(data.selectedInterface);
      }
    } catch (err) {
      setError((err as Error).message || 'Unable to connect to SPIN-IDS backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshInterfaces = useCallback(async () => {
    try {
      const ifaces = await api.getInterfaces();
      setInterfaces(ifaces);
    } catch {
      // Ignored if offline
    }
  }, []);

  useEffect(() => {
    refreshStatus();
    refreshInterfaces();
    const interval = setInterval(refreshStatus, 3000);
    return () => clearInterval(interval);
  }, [refreshStatus, refreshInterfaces]);

  const selectInterface = async (name: string) => {
    setActionLoading(true);
    try {
      const resp = await api.selectInterface(name);
      setSelectedInterface(resp.selectedInterface);
      await refreshStatus();
      return resp;
    } catch (err) {
      setError((err as Error).message);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const startEngine = async () => {
    setActionLoading(true);
    try {
      await api.startEngine();
      await refreshStatus();
    } catch (err) {
      setError((err as Error).message);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const stopEngine = async () => {
    setActionLoading(true);
    try {
      await api.stopEngine();
      await refreshStatus();
    } catch (err) {
      setError((err as Error).message);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const simulateAnomaly = async (req?: SimulationRequest) => {
    setActionLoading(true);
    try {
      const resp = await api.simulateAnomaly(req);
      setLastSimulation(resp);
      await refreshStatus();
      return resp;
    } catch (err) {
      setError((err as Error).message);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  return {
    status,
    interfaces,
    selectedInterface,
    loading,
    actionLoading,
    error,
    lastSimulation,
    startEngine,
    stopEngine,
    simulateAnomaly,
    selectInterface,
    refreshStatus,
    refreshInterfaces,
  };
}
