import { mockService } from '@/mock/mockService';
import { ApiEnvelope } from '@/types/api';

// 当前模式：前端自包含模式 (无需后端，直接由高保真 mockService 驱动)
// 后续后端构建完成后，将 isMock 设置为 false 即可通过代理直连 Spring Boot 18080 端口！
export const IS_MOCK_MODE = true;

class ApiClient {
  private baseUrl: string = '/api/v1';

  async get<T>(path: string, params?: Record<string, any>): Promise<ApiEnvelope<T>> {
    if (IS_MOCK_MODE) {
      return this.dispatchMock<T>('GET', path, params);
    }
    const query = params ? '?' + new URLSearchParams(params).toString() : '';
    const response = await fetch(`${this.baseUrl}${path}${query}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Request-Id': 'req_' + Math.random().toString(36).substring(2, 12)
      },
      credentials: 'include'
    });
    return response.json();
  }

  async post<T>(path: string, body?: any, idempotencyKey?: string): Promise<ApiEnvelope<T>> {
    if (IS_MOCK_MODE) {
      return this.dispatchMock<T>('POST', path, body, idempotencyKey);
    }
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Request-Id': 'req_' + Math.random().toString(36).substring(2, 12)
    };
    if (idempotencyKey) {
      headers['Idempotency-Key'] = idempotencyKey;
    }
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body || {}),
      credentials: 'include'
    });
    return response.json();
  }

  // 模拟请求分发器
  private async dispatchMock<T>(method: string, path: string, payload?: any, _key?: string): Promise<ApiEnvelope<T>> {
    // 模拟微小的真实网络延迟 (30ms - 80ms)
    await new Promise(resolve => setTimeout(resolve, 40));

    if (path === '/auth/me') return mockService.getCurrentUser() as any;
    if (path === '/auth/roles') return mockService.getRoles() as any;
    if (path === '/assets') return mockService.getAssets() as any;
    if (path === '/sensors') return mockService.getSensors() as any;
    if (path.startsWith('/events')) {
      if (path.includes('/transitions')) {
        const id = parseInt(path.split('/')[2]);
        return mockService.updateEventStatus(id, payload.status, payload.reason) as any;
      }
      if (path.includes('/notes')) {
        const id = parseInt(path.split('/')[2]);
        return mockService.addEventInvestigationNote(id, payload.summary, payload.conclusion) as any;
      }
      if (path.includes('/actions')) {
        const id = parseInt(path.split('/')[2]);
        return mockService.requestAction({ eventId: id, ...payload }) as any;
      }
      return mockService.getEvents(payload) as any;
    }
    if (path === '/alerts') return mockService.getAlerts(payload) as any;
    if (path === '/approvals') return mockService.getApprovalTasks() as any;
    if (path.startsWith('/approvals/') && path.endsWith('/decision')) {
      const id = parseInt(path.split('/')[2]);
      return mockService.decideApproval(id, payload.decision, payload.reason) as any;
    }
    if (path === '/models') return mockService.getModels() as any;
    if (path === '/model-release-reviews') return mockService.getReleaseReviews() as any;
    if (path === '/audit') return mockService.getAuditLogs() as any;
    if (path === '/data-sources') return mockService.getDataSources() as any;

    return {
      success: true,
      data: null,
      error: null,
      requestId: 'mock_req'
    } as any;
  }
}

export const apiClient = new ApiClient();
