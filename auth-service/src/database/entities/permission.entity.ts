import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/** Permisos cargados por seed (matriz §5). El código nunca los enumera para autorizar. */
@Entity({ name: 'permissions' })
export class Permission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 80, unique: true })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;
}
