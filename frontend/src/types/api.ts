export interface SubsystemInfo {
  status: string;
  version?: string;
  details?: string;
  runtime?: string;
  model?: string;
  path?: string;
  error?: string;
  interface?: string;
}

export interface EngineStats {
  totalPackets: number;
  totalWindows: number;
  maliciousWindows: number;
  latestPcap?: string;
}

export interface NetworkInterfaceDto {
  name: string;
  displayName: string;
  description: string;
  addresses: string[];
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  macAddress?: string;
  loopback: boolean;
  up: boolean;
  recommended: boolean;
}

export interface StatusResponse {
  engineState: 'RUNNING' | 'STOPPED';
  engineRunning: boolean;
  monitoringMode: 'REAL_INTERFACE' | 'SIMULATION';
  selectedInterface: string;
  interfaceDescription: string;
  thresholdPps: number;
  currentPps: number;
  anomalous: boolean;
  packetsCaptured?: number;
  lastAnomalyTime?: string;
  lastPcapFile?: string;
  captureInProgress: boolean;
  cooldownActive: boolean;
  subsystems: Record<string, SubsystemInfo>;
  stats: EngineStats;
}

export interface RateResponse {
  timestamp: number;
  pps: number;
  threshold: number;
  anomalous: boolean;
  monitoringMode?: 'REAL_INTERFACE' | 'SIMULATION';
  selectedInterface?: string;
  interfaceDescription?: string;
  captureInProgress?: boolean;
  cooldownActive?: boolean;
}

export interface DetectionItem {
  pcapFile: string;
  windowIndex: number;
  flowKey: string;
  prediction: 'NORMAL' | 'MALICIOUS';
  normalProbability: number;
  maliciousProbability: number;
  confidence: number;
  timestamp: string;
}

export interface SimulationRequest {
  burstRate?: number;
  burstPackets?: number;
  targetPort?: number;
}

export interface SimulationResponse {
  success: boolean;
  pcapFile: string;
  capturedPackets: number;
  extractedWindows: number;
  anomalyTriggered: boolean;
  burstRate: number;
  detections: DetectionItem[];
}

export interface PcapFileItem {
  filename: string;
  sizeBytes: number;
  packetCount: number;
  creationTime: string;
}

export interface PacketItem {
  sequence: number;
  protocol: string;
  src: string;
  dst: string;
  length: number;
  direction: 'FORWARD' | 'BACKWARD';
  flags: string;
}

export interface WindowDetail {
  windowIndex: number;
  flowId: string;
  flowIndex: number;
  label: string;
  packetCount: number;
  packets: PacketItem[];
  matrixPreview?: string[];
  detection?: DetectionItem;
}

export interface TelemetryPoint {
  time: string;
  pps: number;
  threshold: number;
  anomalous: boolean;
}

export interface PipelineSseEvent {
  type: 'anomaly' | 'capture_complete' | 'connected' | 'rate' | 'detection';
  timestamp: number;
  rate?: number;
  threshold?: number;
  interface?: string;
  pcapFile?: string;
  packetCount?: number;
}
