import { Entity, ManyToOne, PrimaryKey, Property } from "@mikro-orm/core";
import { BaseEntity } from "../../database/entities/base-entity.entity";
import { User } from "../../users/entities/user.entity";
import { v4 as uuid } from 'uuid';

@Entity({ tableName: "refresh_tokens" })
export class RefreshToken extends BaseEntity {

  @PrimaryKey()
  id: string = uuid();

  @ManyToOne(() => User, { onDelete: "CASCADE", joinColumn: "user_id" })
  user: User;

  @Property({ name: "is_revoked", type: Boolean })
  revoked = false;

  @Property()
  expires: Date;
}
