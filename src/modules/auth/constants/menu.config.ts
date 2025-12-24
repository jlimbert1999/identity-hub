import { UserRole } from 'src/modules/users/entities';

// menu.config.ts
export const MENU_CONFIG: MenuItem[] = [
  {
    label: 'Administración',
    roles: [UserRole.ADMIN],
    items: [
      { label: 'Usuarios', route: '/users' },
      { label: 'Aplicaciones', route: '/apps' },
    ],
  },
  {
    label: 'Mis sistemas',
    roles: [UserRole.USER],
    items: [{ label: 'Mis Apps', route: '/apps' }],
  },
];

export interface MenuItem {
  label: string;
  route?: string;
  roles?: UserRole[];
  items?: MenuItem[];
}
