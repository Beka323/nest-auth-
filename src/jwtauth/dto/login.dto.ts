import { IsString, IsNotEmpty, Length } from "class-validator";

export class LoginUserDto {
    @IsString()
    @IsNotEmpty()
    username: string;
    @IsString()
    @IsNotEmpty()
    @Length(5, 15)
    password: string;
}
