import { Body, Controller, Inject, Post, Request, UseGuards } from "@nestjs/common";
import { ApiBody, ApiCreatedResponse, ApiOkResponse } from "@nestjs/swagger";
import { TokensService } from "src/tokens/tokens.service";
import { UserDto } from "../users/dto/user.dto";
import { AuthService } from "./auth.service";
import { LoginUserBody } from "./dto/login-user.body";
import { LoginUserResponse } from "./dto/login-user.response";
import { RefreshTokenBody } from "./dto/refresh-token.body";
import { RefreshTokenResponse } from "./dto/refresh-token.response";
import { RegisterUserBody } from "./dto/register-user.body";
import { RegisterUserResponse } from "./dto/register-user.response";
import { LocalAuthGuard } from "./guards/local-auth.guard";
import { MD5 } from "crypto-js";
import { AuditLogsService } from "src/audit-logs/audit-logs.service";
import { auditActionTypeENUM } from "src/audit-logs/entities/common";

enum operationType {
  LOGIN = "User Logged In",
}

@Controller("auth")
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokensService: TokensService,
    @Inject(AuditLogsService)
    private auditLog: AuditLogsService
  ) {}

  @UseGuards(LocalAuthGuard)
  @Post("login")
  @ApiBody({ type: LoginUserBody })
  @ApiOkResponse({
    description: "User has been logged in.",
    type: LoginUserResponse,
  })
  async login(@Request() req) {
    console.log("AUTH LOG: ", req);
    const accessToken = await this.authService.generateAccessToken(req.user);
    const refreshToken = await this.authService.generateRefreshToken(
      req.user,
      60 * 60 * 24 * 30,
    );

    const payload = new LoginUserResponse();
    payload.user = new UserDto({
      ...req.user,
      org: req.user.org.name,
    });
    payload.accessToken = accessToken;
    payload.refreshToken = refreshToken;

    console.log(await this.auditLog.create({
      type: auditActionTypeENUM.Create,
      entityType: "auth",
      entityID: req.user.id,
      entityName: req.user.name,
      operationType: operationType.LOGIN,
      valueBefore: null,
      valueAfter: {accessToken: payload.accessToken},
      ref: {},
      owner: req.user.id,
      org: req.user.org.id,
      tableName: "",
    }))
    return payload;
  }

  @Post("refresh")
  @ApiOkResponse({
    description: "Generates a new access token.",
    type: RefreshTokenResponse,
  })
  async refresh(@Body() refreshInput: RefreshTokenBody) {
    console.log(refreshInput.refreshToken);
    const {
      user,
      token,
    } = await this.authService.createAccessTokenFromRefreshToken(
      refreshInput.refreshToken,
    );


    const payload = new RefreshTokenResponse();
    payload.user = new UserDto(user);
    payload.accessToken = token;

    return payload;
  }

  @Post("generateOTP")
  @ApiOkResponse({
    description: "OTP has been generated"
  })
  async generateOTP(@Body() body) {
    const {
      email 
    } = body;

    try {
      const user = await this.authService.findUser(email);
    } catch (err) {
      return err;
    }
    
    

    // If Development Server, static OTP will be used which is "123456"
    // No email will be send for Development server
    // Otp will be send as response to Request
    if (process.env.IsDev === "true") {
      return {
        otp: "123456"
      }
    } else {
      const generatedOtp = await this.tokensService.generateToken(
        email, {
          uuid: false,
          length: 6,
          capitalAlpha: false,
          smallAlpha: false,
          numeric: true,
          specialChar: false
        },
        60000,      // Expiry time of OTP
        "otp",      // Meta for OTP
        null,
        1
      );

      // console.log(generatedOtp);

      // Use generatedOtp.token to send it as Mail
      await this.authService.sendOtpMail(email, generatedOtp.token);

      return {
        // otp: generatedOtp.token,
        msg: `OTP send to ${email} successfully.`
      }
    }

  }

  // @Post("register")
  // @ApiCreatedResponse({
  //   description: "User has been registered.",
  //   type: RegisterUserResponse,
  // })
  // async register(@Body() registerInput: RegisterUserBody) {
  //   const user = await this.authService.register(
  //     registerInput.username,
  //     registerInput.password,
  //   );

  //   const accessToken = await this.authService.generateAccessToken(user);
  //   const refreshToken = await this.authService.generateRefreshToken(
  //     user,
  //     60 * 60 * 24 * 30,
  //   );

  //   const payload = new RegisterUserResponse();
  //   payload.user = new UserDto(user);
  //   payload.accessToken = accessToken;
  //   payload.refreshToken = refreshToken;

  //   return payload;
  // }
}
