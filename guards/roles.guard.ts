import { Injectable, CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { rolesEnum as Role } from "../../users/entities/common"; 

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    ) {}
  canActivate(context: ExecutionContext): boolean {
    const requireRoles = this.reflector.getAllAndOverride<Role[]>("roles", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requireRoles) {
      return true;
    }
    const { headers }=context.switchToHttp().getRequest();
    const user = JSON.parse(headers.user);
    console.log('request ---- ' , requireRoles, user )
    return requireRoles.some((role) => user['role'] == role);
  }
}