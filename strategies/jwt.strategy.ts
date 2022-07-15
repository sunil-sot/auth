import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../../users/users.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>("auth.jwtKey"),
      signOptions: { expiresIn: "15m" },
    });
  }

  async validate(payload: any) {
    console.log("jkshdjksdkfkljdklsdj")
    const { sub: id } = payload;
    console.log(payload)
    const user = await this.usersService.getUser(id);
    return user;
  }
}
