// Consolidated into ../api.js to avoid duplicate API clients
export {
  fetchHealth as checkHealth,
  submitScan as startScan,
  fetchScanHistory,
  fetchScanById as fetchScanDetails,
} from "../api";
