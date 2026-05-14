import axios from "axios";

const API = "http://localhost:8000/api";

export const analyzeMessage = async (data) => {
  const res = await axios.post(`${API}/analyze`, data);
  return res.data;
};

export const getHistory = async () => {
  const res = await axios.get(`${API}/history`);
  return res.data;
};