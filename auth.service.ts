import { EntityRepository } from "@mikro-orm/core";
import { InjectRepository } from "@mikro-orm/nestjs";
import { Inject, Injectable, UnprocessableEntityException } from "@nestjs/common";
import { JwtService, JwtSignOptions } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import * as bcrypt from "bcrypt";
import { TokenExpiredError } from "jsonwebtoken";
import { NotificationsService } from "src/notifications/notifications.service";
import { TokensService } from "src/tokens/tokens.service";
import { User } from "../users/entities/user.entity";
import { UsersService } from "../users/users.service";
import { RefreshToken } from "./entities/refresh-token.entity";
import { AuditLogsService } from "src/audit-logs/audit-logs.service";
import { auditActionTypeENUM } from "src/audit-logs/entities/common";

enum operationType {
  LOGIN_FAILED = "Unauthorized Login Attempt",
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: EntityRepository<RefreshToken>,
    private tokensService: TokensService,
    private notificationService: NotificationsService,
    private config: ConfigService,
    @Inject(AuditLogsService)
    private auditLog: AuditLogsService
  ) {}

  async validateUser(username: string, token: string) {
    const user = await this.usersService.getUser(username);
    if (user) {
      const { ...result } = user;

      // Dev Static OTP validation required here
      if (process.env.IsDev === "true") {
        if(token == "123456") return result;
      }
      
      try {
        const tokenValidation = await this.tokensService.verifyToken(username, token);
        return result;
      } catch (e) {
        console.log('errro ', e , typeof e);
        // e = JSON.stringify(e);
        const owner : any = user.id;
        console.log(await this.auditLog.create({
          type: auditActionTypeENUM.Create,
          entityType: "auth",
          entityID: user.id,
          entityName: user.name,
          operationType: operationType.LOGIN_FAILED,
          valueBefore: null,
          valueAfter: {message: e.message},
          ref: {},
          owner,
          org: user.org.id,
          tableName: "",
        }));
        return null;
      }
    }
    return null;
  }

  async generateAccessToken(user: Pick<User, "id">) {
    const payload = { sub: String(user.id) };
    return await this.jwtService.signAsync(payload);
  }

  async createRefreshToken(user: Pick<User, "id">, ttl: number) {
    const expiration = new Date();
    expiration.setTime(expiration.getTime() + ttl);

    const token = this.refreshTokenRepository.create({
      user,
      expires: expiration,
    });

    await this.refreshTokenRepository.persistAndFlush(token);

    return token;
  }

  async generateRefreshToken(user: Pick<User, "id">, expiresIn: number) {
    const payload = { sub: String(user.id) };
    const token = await this.createRefreshToken(user, expiresIn);

    return await this.jwtService.signAsync({ 
      sub: String(user.id),
      jwtId: String(token.id)
    }, {
      expiresIn: '1d'
    });
  }

  async resolveRefreshToken(encoded: string) {
    try {
      const payload = await this.jwtService.verify(encoded);

      if (!payload.sub || !payload.jwtId) {
        throw new UnprocessableEntityException("Refresh token malformed");
      }

      const token = await this.refreshTokenRepository.findOne({
        id: payload.jwtId,
      });

      
      if (!token) {
        throw new UnprocessableEntityException("Refresh token not found");
      }

      if (token.revoked) {
        throw new UnprocessableEntityException("Refresh token revoked");
      }

      const user = await this.usersService.getUser(payload.sub);

      if (!user) {
        throw new UnprocessableEntityException("Refresh token malformed");
      }

      return { user, token };
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnprocessableEntityException("Refresh token expired");
      } else {
        throw new UnprocessableEntityException("Refresh token malformed");
      }
    }
  }

  async createAccessTokenFromRefreshToken(refresh: string) {
    const { user } = await this.resolveRefreshToken(refresh);

    const token = await this.generateAccessToken(user);

    return { user, token };
  }

  async sendOtpMail(email: string, otp: string) {
    const sourceIdentity = this.config.get<string>('aws.sesSourceIdentity');
    
    const emailHtml = `OTP: ${otp}`;

    try {
      await this.notificationService.sendEmail({
        emails: [email],
        subject: "Login OTP",
        html: emailHtml,
        source: sourceIdentity
      });
    } catch (e) {
      console.log(e);
    }

  }

  async findUser(email: string) {
    return await this.usersService.getUser(email);
  }

  // async register(username: string, pass: string) {
  //   let user = await this.usersService.findOne({ username });
  //   if (user) {
  //     return null;
  //   }
  //   const hashed = await bcrypt.hash(pass, 10);
  //   user = await this.usersService.create({ username, password: hashed });
  //   return user;
  // }
}
