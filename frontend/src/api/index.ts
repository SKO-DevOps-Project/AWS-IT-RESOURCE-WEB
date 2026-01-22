import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle 401 errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token } = response.data;
          localStorage.setItem('access_token', access_token);

          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        } catch (refreshError) {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
        }
      }
    }

    return Promise.reject(error);
  }
);

export interface Ticket {
  request_id: string;
  requester_name: string;
  requester_mattermost_id: string;
  iam_user_name: string;
  env: string;
  service: string;
  permission_type: string;
  target_services: string[];
  start_time: string;
  end_time: string;
  purpose: string;
  status: string;
  role_arn?: string;
  policy_arn?: string;
  approver_id?: string;
  created_at: string;
  updated_at: string;
}

export interface Activity {
  log_id: string;
  role_name: string;
  role_arn: string;
  session_name: string;
  iam_user_name: string;
  event_time: string;
  event_name: string;
  event_source: string;
  aws_region: string;
  source_ip: string;
  user_agent: string;
  error_code?: string;
  error_message?: string;
  resources: string[];
  raw_event: string;
}

export interface Service {
  key: string;
  name: string;
  display: string;
}

export interface WorkRequest {
  request_id: string;
  service_name: string;
  service_display_name: string;
  start_date: string;
  end_date: string;
  description: string;
  requester_name: string;
  created_at: string;
  status: string;
}

export interface User {
  user_id: string;
  name: string;
  email: string;
  phone_number?: string;
  team: string;
  region: string;
  job_title?: string;
  is_admin: boolean;
  last_login?: string;
  created_at?: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export const getTickets = async (params?: {
  status?: string;
  user_name?: string;
  limit?: number;
}) => {
  const response = await api.get('/tickets', { params });
  return response.data;
};

export const getTicketDetail = async (requestId: string) => {
  const response = await api.get(`/tickets/${requestId}`);
  return response.data;
};

export const getActivities = async (params?: {
  user_name?: string;
  start_time?: string;
  end_time?: string;
  event_name?: string;
  limit?: number;
}) => {
  const response = await api.get('/activities', { params });
  return response.data;
};

export const getUserActivities = async (iamUserName: string, params?: {
  start_time?: string;
  end_time?: string;
}) => {
  const response = await api.get(`/users/${iamUserName}/activities`, { params });
  return response.data;
};

export const getServices = async () => {
  const response = await api.get('/services');
  return response.data;
};

export const getWorkRequests = async (params?: {
  service_name?: string;
  status?: string;
  limit?: number;
}) => {
  const response = await api.get('/work-requests', { params });
  return response.data;
};

export const createWorkRequest = async (data: {
  service_name: string;
  start_date: string;
  end_date: string;
  description: string;
  requester_name: string;
}) => {
  const response = await api.post('/work-requests', data);
  return response.data;
};

export const updateWorkRequestStatus = async (requestId: string, status: string) => {
  const response = await api.patch(`/work-requests/${requestId}`, { status });
  return response.data;
};

export const getWorkRequestDetail = async (requestId: string) => {
  const response = await api.get(`/work-requests/${requestId}`);
  return response.data;
};

export const getWorkRequestTickets = async (requestId: string) => {
  const response = await api.get(`/work-requests/${requestId}/tickets`);
  return response.data;
};

export const updateTicketWorkRequest = async (ticketId: string, workRequestId: string | null) => {
  const response = await api.patch(`/tickets/${ticketId}`, { work_request_id: workRequestId });
  return response.data;
};

// Auth APIs
export const login = async (userId: string, password: string): Promise<LoginResponse> => {
  const response = await api.post('/auth/login', { user_id: userId, password });
  return response.data;
};

export const getMe = async () => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const refreshToken = async (refreshToken: string) => {
  const response = await api.post('/auth/refresh', { refresh_token: refreshToken });
  return response.data;
};

export default api;
