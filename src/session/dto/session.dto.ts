import { IsNotEmpty, IsString, Length, IsEmail } from "class-validator";
export class SessionUserDto {
    @IsString()
    @IsNotEmpty()
    username: string;
    @IsString()
    @IsNotEmpty()
    @IsEmail()
    email: string;
    @IsString()
    @IsNotEmpty()
    @Length(5, 25)
    password: string;
}
