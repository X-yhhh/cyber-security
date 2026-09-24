export interface ApiEnvelope<T> {
  success: boolean;
  data: T | null;
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
  } | null;
  requestId: string;
}

export interface PagedResult<T> {
  totalElements: number;
  page: number;
  size: number;
  items: T[];
}

export interface CommonQueryParams {
  page?: number;
  size?: number;
  search?: string;
  status?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}
