import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Esquema de identidad de AUTH (§3). SQL explícito: las restricciones viven en la BD,
 * no solo en el ORM. gen_random_uuid() es nativo desde PostgreSQL 13.
 */
export class InitIdentitySchema1793836800000 implements MigrationInterface {
  name = 'InitIdentitySchema1793836800000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE users (
        id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
        username      varchar(50)  NOT NULL,
        email         varchar(254) NOT NULL,
        password_hash text         NOT NULL,
        status        varchar(16)  NOT NULL DEFAULT 'active',
        created_at    timestamptz  NOT NULL DEFAULT now(),
        updated_at    timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT uq_users_username UNIQUE (username),
        CONSTRAINT uq_users_email    UNIQUE (email),
        CONSTRAINT ck_users_status   CHECK (status IN ('active', 'inactive'))
      )`);

    await q.query(`
      CREATE TABLE roles (
        id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
        name        varchar(50) NOT NULL,
        description text,
        status      varchar(16) NOT NULL DEFAULT 'active',
        created_at  timestamptz NOT NULL DEFAULT now(),
        updated_at  timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_roles_name   UNIQUE (name),
        CONSTRAINT ck_roles_status CHECK (status IN ('active', 'inactive'))
      )`);

    await q.query(`
      CREATE TABLE user_roles (
        id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     uuid        NOT NULL,
        role_id     uuid        NOT NULL,
        assigned_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_user_roles_user_role UNIQUE (user_id, role_id),
        CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id)
          REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id)
          REFERENCES roles (id) ON DELETE CASCADE
      )`);
    await q.query(`CREATE INDEX ix_user_roles_role_id ON user_roles (role_id)`);

    await q.query(`
      CREATE TABLE permissions (
        id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
        name        varchar(80) NOT NULL,
        description text,
        CONSTRAINT uq_permissions_name UNIQUE (name)
      )`);

    await q.query(`
      CREATE TABLE role_permissions (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        role_id       uuid NOT NULL,
        permission_id uuid NOT NULL,
        CONSTRAINT uq_role_permissions_role_permission UNIQUE (role_id, permission_id),
        CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id)
          REFERENCES roles (id) ON DELETE CASCADE,
        CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id)
          REFERENCES permissions (id) ON DELETE CASCADE
      )`);

    await q.query(`
      CREATE TABLE revoked_tokens (
        jti        uuid        PRIMARY KEY,
        user_id    uuid        NOT NULL,
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT fk_revoked_tokens_user FOREIGN KEY (user_id)
          REFERENCES users (id) ON DELETE CASCADE
      )`);
    await q.query(
      `CREATE INDEX ix_revoked_tokens_expires_at ON revoked_tokens (expires_at)`,
    );
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE revoked_tokens`);
    await q.query(`DROP TABLE role_permissions`);
    await q.query(`DROP TABLE permissions`);
    await q.query(`DROP TABLE user_roles`);
    await q.query(`DROP TABLE roles`);
    await q.query(`DROP TABLE users`);
  }
}
