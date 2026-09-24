import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router';
import MainLayout from '@/components/layout/MainLayout.vue';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/LoginView.vue'),
    meta: { title: '登录控制台' }
  },
  {
    path: '/',
    component: MainLayout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/DashboardView.vue'),
        meta: { title: '安全态势感知大屏' }
      },
      {
        path: 'incidents',
        name: 'Incidents',
        component: () => import('@/views/incidents/IncidentListView.vue'),
        meta: { title: '威胁告警与事件研判' }
      },
      {
        path: 'incidents/:id',
        name: 'IncidentDetail',
        component: () => import('@/views/incidents/IncidentDetailView.vue'),
        meta: { title: '事件研判工作台' }
      },
      {
        path: 'incidents/alerts',
        name: 'AlertList',
        component: () => import('@/views/incidents/AlertListView.vue'),
        meta: { title: '原始流量告警池' }
      },
      {
        path: 'response',
        name: 'Approvals',
        component: () => import('@/views/response/ApprovalListView.vue'),
        meta: { title: '受控防御审批' }
      },
      {
        path: 'response/ledger',
        name: 'ExecutionLedger',
        component: () => import('@/views/response/ExecutionLedgerView.vue'),
        meta: { title: '防御执行台账与安全回滚' }
      },
      {
        path: 'assets',
        name: 'Assets',
        component: () => import('@/views/assets/AssetInventoryView.vue'),
        meta: { title: '资产台账与授权管理' }
      },
      {
        path: 'assets/sensors',
        name: 'SensorMonitor',
        component: () => import('@/views/assets/SensorMonitorView.vue'),
        meta: { title: '软件传感器健康监控' }
      },
      {
        path: 'datasources',
        name: 'DataSources',
        component: () => import('@/views/datasources/DataSourceView.vue'),
        meta: { title: '数据源管理与接入' }
      },
      {
        path: 'datasources/mappings',
        name: 'Mappings',
        component: () => import('@/views/datasources/MappingView.vue'),
        meta: { title: '字段映射与质量门禁' }
      },
      {
        path: 'models',
        name: 'ModelRegistry',
        component: () => import('@/views/models/ModelRegistryView.vue'),
        meta: { title: '模型治理与不可变Manifest' }
      },
      {
        path: 'models/release-reviews',
        name: 'ReleaseReviews',
        component: () => import('@/views/models/ReleaseReviewView.vue'),
        meta: { title: '独立模型发布审查' }
      },
      {
        path: 'models/drift',
        name: 'DriftFeedback',
        component: () => import('@/views/models/DriftFeedbackView.vue'),
        meta: { title: '特征分布漂移与人工反馈' }
      },
      {
        path: 'models/training-jobs',
        name: 'TrainingJobs',
        component: () => import('@/views/models/TrainingJobView.vue'),
        meta: { title: 'Windows离线训练任务' }
      },
      {
        path: 'replay',
        name: 'Replay',
        component: () => import('@/views/replay/ReplayView.vue'),
        meta: { title: '隔离靶场演练与流量回放' }
      },
      {
        path: 'audit',
        name: 'AuditLogs',
        component: () => import('@/views/audit/AuditLogView.vue'),
        meta: { title: '安全审计日志与合规追踪' }
      },
      {
        path: 'iam',
        name: 'UserManagement',
        component: () => import('@/views/iam/UserManagementView.vue'),
        meta: { title: '访问控制与系统运维' }
      }
    ]
  }
];

export const router = createRouter({
  history: createWebHistory(),
  routes
});

router.afterEach((to) => {
  if (to.meta.title) {
    document.title = `${to.meta.title} | SecOps Console`;
  }
});
