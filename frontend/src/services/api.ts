import type {
  StatusResponse,
  RateResponse,
  DetectionItem,
  SimulationRequest,
  SimulationResponse,
  PcapFileItem,
  WindowDetail,
  NetworkInterfaceDto,
} from '../types/api';

const API_BASE = '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.error) errorMsg = errJson.error;
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }
  return res.json();
}

export const api = {
  async getStatus(): Promise<StatusResponse> {
    const res = await fetch(`${API_BASE}/status`);
    return handleResponse<StatusResponse>(res);
  },

  async getTelemetryRate(): Promise<RateResponse> {
    const res = await fetch(`${API_BASE}/telemetry/rate`);
    return handleResponse<RateResponse>(res);
  },

  async getInterfaces(): Promise<NetworkInterfaceDto[]> {
    const res = await fetch(`${API_BASE}/interfaces`);
    return handleResponse<NetworkInterfaceDto[]>(res);
  },

  async getEngineInterface(): Promise<{ selectedInterface: string; description: string; monitoringMode: string }> {
    const res = await fetch(`${API_BASE}/engine/interface`);
    return handleResponse<{ selectedInterface: string; description: string; monitoringMode: string }>(res);
  },

  async selectInterface(interfaceName: string): Promise<{ status: string; selectedInterface: string; description: string; message: string }> {
    const res = await fetch(`${API_BASE}/engine/interface`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interfaceName }),
    });
    return handleResponse<{ status: string; selectedInterface: string; description: string; message: string }>(res);
  },

  async startEngine(): Promise<{ status: string; interface?: string; message: string }> {
    const res = await fetch(`${API_BASE}/engine/start`, { method: 'POST' });
    return handleResponse<{ status: string; interface?: string; message: string }>(res);
  },

  async stopEngine(): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/engine/stop`, { method: 'POST' });
    return handleResponse<{ status: string; message: string }>(res);
  },

  async simulateAnomaly(req: SimulationRequest = {}): Promise<SimulationResponse> {
    const res = await fetch(`${API_BASE}/engine/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    return handleResponse<SimulationResponse>(res);
  },

  async getDetections(label = 'ALL', limit = 50): Promise<DetectionItem[]> {
    const params = new URLSearchParams();
    if (label && label !== 'ALL') params.append('label', label);
    if (limit) params.append('limit', limit.toString());

    const res = await fetch(`${API_BASE}/detections?${params.toString()}`);
    return handleResponse<DetectionItem[]>(res);
  },

  async getPcaps(): Promise<PcapFileItem[]> {
    const res = await fetch(`${API_BASE}/pcaps`);
    return handleResponse<PcapFileItem[]>(res);
  },

  getPcapDownloadUrl(filename: string): string {
    return `${API_BASE}/pcaps/download?file=${encodeURIComponent(filename)}`;
  },

  async getWindows(): Promise<WindowDetail[]> {
    const res = await fetch(`${API_BASE}/windows`);
    return handleResponse<WindowDetail[]>(res);
  },

  async getWindowDetail(index: number): Promise<WindowDetail> {
    const res = await fetch(`${API_BASE}/windows/detail?index=${index}`);
    return handleResponse<WindowDetail>(res);
  },

  async getLogs(format: 'json' | 'csv' = 'json'): Promise<DetectionItem[] | string> {
    const res = await fetch(`${API_BASE}/logs?format=${format}`);
    if (format === 'csv') {
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch CSV log`);
      return res.text();
    }
    return handleResponse<DetectionItem[]>(res);
  },

  getLogsCsvUrl(): string {
    return `${API_BASE}/logs?format=csv`;
  },
};
