export interface ChangelogItem {
  type: 'new' | 'improved' | 'fixed';
  text: string;
}

export interface ChangelogEntry {
  version: string;
  date: string;
  title: string;
  showUntil: string; // 자동 팝업 마지막 날짜 (YYYY-MM-DD)
  items: ChangelogItem[];
}

const changelog: ChangelogEntry[] = [
  {
    version: '1.2.0',
    date: '2026-03-04',
    title: '나의 요청 & 알림 개선',
    showUntil: '2026-03-07',
    items: [
      { type: 'new', text: '나의 권한 요청 목록 페이지 추가' },
      { type: 'improved', text: '권한 요청 시 Mattermost 알림 개선' },
      { type: 'improved', text: 'Billing 선택 시 환경/서비스 검증 스킵' },
      { type: 'fixed', text: 'Mattermost 알림 target_services 리스트 처리 수정' },
    ],
  },
  {
    version: '1.0.0',
    date: '2026-02-01',
    title: '최초 출시',
    showUntil: '2026-02-04',
    items: [
      { type: 'new', text: 'AWS 역할 권한 요청 시스템 출시' },
      { type: 'new', text: '대시보드, 권한 요청, 승인/반려 기능' },
      { type: 'new', text: '활동 로그 및 업무 요청 관리' },
    ],
  },
];

export const CURRENT_VERSION = changelog[0].version;
export default changelog;
