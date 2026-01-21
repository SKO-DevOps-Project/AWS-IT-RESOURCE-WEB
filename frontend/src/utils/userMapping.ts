// Mattermost ID -> 실명 매핑
export const mattermostToName: Record<string, string> = {
  'beom-jun': '김범준',
  'cation98': '최종언',
  'hojinchang': '장호진',
  'ibr': '인병렬',
  'jason': '장덕현',
  'leejinsoo': '이진수',
  'parkjeongyeon': '박정연',
  'seongwoo.cho': '조성우',
  'woong.heo': '허웅',
};

// IAM User명 -> 실명 매핑
export const iamUserToName: Record<string, string> = {
  'N1104005': '김범준',
  'cation98': '최종언',
  'hchang': '장호진',
  'N1103874': '인병렬',
  'duckfal': '장덕현',
  'N1104268': '이진수',
  'jeongyeon': '박정연',
  'he12569': '조성우',
  'N1104262': '허웅',
};

// IAM 사용자 목록 (드롭다운용)
export const iamUserList = [
  { name: '김범준', iamUser: 'N1104005' },
  { name: '최종언', iamUser: 'cation98' },
  { name: '장호진', iamUser: 'hchang' },
  { name: '인병렬', iamUser: 'N1103874' },
  { name: '장덕현', iamUser: 'duckfal' },
  { name: '이진수', iamUser: 'N1104268' },
  { name: '박정연', iamUser: 'jeongyeon' },
  { name: '조성우', iamUser: 'he12569' },
  { name: '허웅', iamUser: 'N1104262' },
];

// Mattermost ID로 실명 가져오기
export const getNameByMattermost = (mattermostId: string): string => {
  return mattermostToName[mattermostId] || mattermostId;
};

// IAM User명으로 실명 가져오기
export const getNameByIamUser = (iamUser: string): string => {
  return iamUserToName[iamUser] || iamUser;
};

// IAM User명으로 표시명 가져오기 (이름(IAM))
export const getDisplayNameByIamUser = (iamUser: string): string => {
  const name = iamUserToName[iamUser];
  return name ? `${name}(${iamUser})` : iamUser;
};
