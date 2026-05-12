const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

type InitialConfig = RequestInit & { requiresAuth?: boolean };

async function fetcher(endpoint: string, config: InitialConfig = {}, isDownload = false) {
  const { requiresAuth = true, ...customConfig } = config;
  const headers: Record<string, string> = { ...(customConfig.headers as Record<string, string>) };

  if (requiresAuth) {
    const token = typeof window !== "undefined" ? localStorage.getItem("masvs_token") : null;
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  // Auto-set Content-Type if it's not FormData
  if (!(customConfig.body instanceof FormData) && !isDownload) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...customConfig,
    headers,
  });

  if (!response.ok) {
    if (response.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("masvs_token");
        window.location.href = "/login";
      }
    }
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `API Error: ${response.status} ${response.statusText}`);
  }

  if (isDownload) {
    return response.blob();
  }

  // Handle 204 No Content
  if (response.status === 204) return null;

  return response.json();
}

export const api = {
  get: (endpoint: string, requiresAuth = true) => 
    fetcher(endpoint, { method: "GET", requiresAuth }),
  
  post: (endpoint: string, body: any, requiresAuth = true) => 
    fetcher(endpoint, { method: "POST", body: JSON.stringify(body), requiresAuth }),
    
  patch: (endpoint: string, body: any, requiresAuth = true) => 
    fetcher(endpoint, { method: "PATCH", body: JSON.stringify(body), requiresAuth }),

  delete: (endpoint: string, requiresAuth = true) => 
    fetcher(endpoint, { method: "DELETE", requiresAuth }),

  upload: (endpoint: string, formData: FormData, requiresAuth = true) =>
    fetcher(endpoint, { method: "POST", body: formData, requiresAuth }),
    
  download: (endpoint: string, requiresAuth = true) => 
    fetcher(endpoint, { method: "GET", requiresAuth }, true),
    
  getWsUrl: (endpoint: string) => {
    const url = new URL(API_BASE_URL);
    const wsProtocol = url.protocol === "https:" ? "wss:" : "ws:";
    return `${wsProtocol}//${url.host}${url.pathname}${endpoint}`;
  }
};
