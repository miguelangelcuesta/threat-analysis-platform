import axios from "axios";
import { getDeviceId } from "../utils/device";

const API = process.env.REACT_APP_BACKEND_URL;

const client = axios.create({
  baseURL: `${API}/api`,
});

client.interceptors.request.use((config) => {
  config.headers["X-Device-ID"] = getDeviceId();
  return config;
});

export default client;