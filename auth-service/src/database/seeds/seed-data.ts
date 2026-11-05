/**
 * Datos iniciales que el seed escribe en la BD (matriz §5).
 * La autorización NUNCA lee este archivo: consulta las tablas permissions/role_permissions.
 */
export const SEED_ROLES = [
  {
    name: 'ADMIN',
    description: 'Administración de usuarios, roles y asignaciones',
  },
  { name: 'ANALYST', description: 'Análisis esteganográfico de imágenes' },
  { name: 'USER', description: 'Usuario básico del chat' },
] as const;

export const SEED_PERMISSIONS = [
  { name: 'profile.read', description: 'Leer el propio perfil' },
  { name: 'users.manage', description: 'Gestionar usuarios' },
  { name: 'roles.manage', description: 'Gestionar roles' },
  { name: 'user_roles.manage', description: 'Asignar y revocar roles' },
  { name: 'steganography.analyze', description: 'Enviar imágenes a análisis' },
  {
    name: 'steganography.results.read_own',
    description: 'Leer los análisis propios',
  },
  {
    name: 'steganography.results.read_any',
    description: 'Leer cualquier análisis',
  },
] as const;

type RoleName = (typeof SEED_ROLES)[number]['name'];
type PermissionName = (typeof SEED_PERMISSIONS)[number]['name'];

export const SEED_ROLE_PERMISSIONS: Record<RoleName, PermissionName[]> = {
  ADMIN: SEED_PERMISSIONS.map((p) => p.name),
  ANALYST: [
    'profile.read',
    'steganography.analyze',
    'steganography.results.read_own',
  ],
  USER: ['profile.read'],
};
