import { User } from "../entities/User";
import { MyContext } from "src/types";
import {Resolver,Query, Mutation, Arg, InputType, Field, Ctx, ObjectType} from "type-graphql"
import argon2 from "argon2"
import { UniqueDirectiveNamesRule } from "graphql";
//import { Field } from "@mikro-orm/postgresql";

@InputType()
class UsernamePasswordInput{
    @Field()
    username: string;
    @Field()
    password: string;
}

@ObjectType()
class FieldError{
    @Field()
    field: string;
    @Field()
    message: string;

}

@ObjectType()
class UserResponse{
    @Field(()=> [FieldError],{nullable:true})
    errors?: FieldError[];

    @Field(() => User, {nullable:true})
    user?: User;
}

@Resolver()
export class UserResolver{

    @Query(()=> User, {nullable:true})
    async me(@Ctx(){req,em}: MyContext){

        if (!req.session.userId) {
            return null;
        }

        const user=await em.findOne(User,{id :req.session.userId});
        return user;
    }



   
    @Mutation(() => UserResponse)
    async register(
        @Arg('options') options:UsernamePasswordInput,
        @Ctx(){ em }:MyContext
    ):Promise<UserResponse>{

        const exists= await em.findOne(User,{username:options.username});
        if (exists) {
            return{
                errors:[{
                    field:'username',
                    message:"This username already exist"
                }]
            }
        }

        if (options.username.length<= 2) {
            return{
                errors:[{
                    field:'username',
                    message:'length must be greater than 2'
                },
             ],
            };
        }

        if (options.password.length<= 3) {
            return{
                errors:[{
                    field:'password',
                    message:'length must be greater than 3'
                },
             ],
            };
        }

        const hashedPassword= await argon2.hash(options.password)
        const user=em.create(User,{username:options.username,password:hashedPassword});
        await em.persistAndFlush(user)
        return {user};
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options') options:UsernamePasswordInput,
        @Ctx(){ em ,req}:MyContext
    ): Promise<UserResponse>{
        const user= await em.findOne(User,{username:options.username});
        if (!user) {
            return{
                errors:[{
                    field:'username',
                    message:"Username does'nt exist"
                }]
            }
        }
        const valid= await argon2.verify(user.password,options.password);
        if (!valid) {
            return{
                errors:[{
                    field: "password",
                    message:"Incorrect password"
                }
                ]
            }
        }

       
        //Logic of how it works
        // FIRST:  User.id will be stored at Redis  Ex: SebastianId: 15 => keyinredis123
        // SECOND : Express-session will set a cookie on the browser , also this will be encrypted, EX: keyinredis123encryptedway
        // THIRD: When user makes a request keyinredis123encryptedway will be sended to the server
        // FOUR: Session will decrypt the cookie  then keyinredis123encryptedway will be => keyinredis123
        // FIFTH : Server will make a request to redis where keyinredis123 will be = to SebastianId:15

        // userId will be the name of the variable that will be stored in req.session ex: console.log(req.session) will show user.id
        req.session.userId=user.id;

        return {user};
    }

}