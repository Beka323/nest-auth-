import {
    Controller,
    Post,
    Body,
    ValidationPipe,
    Res,
    Req,
    UseGuards,
    Param,
    Get,
    Patch
} from "@nestjs/common";
import { JwtauthService } from "./jwtauth.service";
import { CreateUserDto } from "./dto/user.dto";
import { LoginUserDto } from "./dto/login.dto";
import { Response, Request } from "express";
import { JwtGuard } from "./guard/jwt.guard";
import { UpdateUserDto } from "./dto/update.dto";

@Controller("jwtauth")
export class JwtauthController {
    constructor(private jwtAuthService: JwtauthService) {}
    @Post("register")
    async register(@Body(ValidationPipe) createUser: CreateUserDto): Promise<{
        msg: string;
        status: boolean;
    }> {
        return this.jwtAuthService.registerUser(createUser);
    }
    @Post("login")
    async login(
        @Body(ValidationPipe) user: LoginUserDto,
        @Res({ passthrough: true }) response: Response
    ): Promise<{ accessToken: string }> {
        return this.jwtAuthService.login(user, response);
    }
    @UseGuards(JwtGuard)
    @Get("user/:id")
    async getUser(@Param("id") id: string): Promise<any> {
        return this.jwtAuthService.getUser(id);
    }
    @UseGuards(JwtGuard)
    @Patch("updateuser/:id")
    async updateUser(
        @Param("id") id: string,
        @Body(ValidationPipe) updateUser: UpdateUserDto
    ): Promise<any> {
        return this.jwtAuthService.updateUser(id, updateUser);
    }
    @Get("refresh-token")
    async refreshToken(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<any> {
        return this.jwtAuthService.refreshToken(req,res);
    }
}
