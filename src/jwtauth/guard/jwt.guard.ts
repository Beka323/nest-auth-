import {
    Injectable,
    ExecutionContext,
    CanActivate,
    UnauthorizedException,
    BadRequestException
} from "@nestjs/common";

import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class JwtGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        private configService: ConfigService
    ) {}
    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const headers =
            request.headers.authorization || request.headers.Authorization;
        if (!headers) {
            throw new UnauthorizedException("un authorized user");
        }
        const secret = this.configService.get<string>("JWT_SECRET");

        const token = headers.split(" ")[1];
        try {
            const verifedUser = await this.jwtService.verifyAsync(token, {
                secret: secret
            });
            request["user"] = verifedUser;
            return true;
        } catch {
            throw new BadRequestException("invalid token");
        }
    }
}
