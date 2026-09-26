import type { RoleName } from './common'

export interface CurrentUser {
  name: string
  role: RoleName
  initials: string
  email: string
  title: string
}
