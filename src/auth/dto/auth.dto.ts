/* eslint-disable prettier/prettier */

import { IsEmail, IsNotEmpty, IsString, Length } from "class-validator";



export class AuthDto {
    @IsEmail()
    public email: string;


    @IsNotEmpty()
    @IsString()
    @Length(3, 20, {  message: 'Password to be between 3, 20 characters'})
    public password: string
}