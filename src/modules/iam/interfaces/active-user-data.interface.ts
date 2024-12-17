import { UserRole, Permission } from '@prisma/client';

export interface ActiveUserData {
  sub: string;
  email: string;
  role: UserRole;
  permissions: Permission[];
}
