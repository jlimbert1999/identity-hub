import { Injectable } from '@nestjs/common';
import { MENU_CONFIG, MenuItem } from '../constants/menu.config';
import { User, UserRole } from 'src/modules/users/entities';

@Injectable()
export class AuthService {
  getUserAuthData(user: User) {
    const menu = this.filterMenuByRoles(MENU_CONFIG, user.roles);
    return { user, menu };
  }

  private filterMenuByRoles(menu: MenuItem[], userRoles: UserRole[]) {
    return menu
      .map(({ roles, ...section }) => {
        const sectionRoles = roles;

        const canSeeSection =
          !sectionRoles ||
          sectionRoles.some((role) => userRoles.includes(role));

        if (!canSeeSection) return null;

        // 3️⃣ Filtrar items hijos (si existen)
        let filteredItems: MenuItem[] | undefined;

        if (section.items) {
          filteredItems = section.items.filter((item) => {
            const itemRoles = item.roles ?? sectionRoles;

            return (
              !itemRoles || itemRoles.some((role) => userRoles.includes(role))
            );
          });
        }

        // 4️⃣ Si era contenedor y se quedó sin hijos → ocultar
        if (section.items && (!filteredItems || filteredItems.length === 0)) {
          return null;
        }

        // 5️⃣ Retornar COPIA (no mutar)
        return {
          ...section,
          items: filteredItems,
        };
      })
      .filter((item) => item !== null);
  }
}
