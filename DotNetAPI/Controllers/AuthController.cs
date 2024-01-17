using System.Data;
using AutoMapper;
using Dapper;
using DotnetAPI.Data;
using DotnetAPI.DTO;
using DotnetAPI.Helpers;
using DotnetAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace DotnetAPI.Controllers{
   

    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase {

        private readonly DataContextDapper _dapper; 
        private readonly AuthHelper _authHelper;
        private readonly ReusableSql _reusableSql;
        private readonly IMapper _mapper;

        public AuthController(IConfiguration config){
            _dapper = new DataContextDapper(config);
            _authHelper = new AuthHelper(config);
            _reusableSql = new ReusableSql(config);
            _mapper = new Mapper(new MapperConfiguration(config => {
                config.CreateMap<UserForRegistrationDTO, UserComplete>();
            }));
        }
 
        [AllowAnonymous]
        [HttpPost("Register")]
        public IActionResult Register(UserForRegistrationDTO uFR){
            if (uFR.Password == uFR.PasswordConfirm){
                string sqlCheckUserExists = "SELECT Email FROM TutorialAppSchema.Auth WHERE Email = '" + uFR.Email + "'";

                IEnumerable<string> existingUsers = _dapper.LoadData<string>(sqlCheckUserExists);
                if(existingUsers.Count() == 0){
                   
                    UserForLoginDTO userForSetPassword = new UserForLoginDTO(){
                        Email = uFR.Email,
                        Password = uFR.Password
                    };

                    if (_authHelper.SetPassword(userForSetPassword)){
                        
                        UserComplete userComplete = _mapper.Map<UserComplete>(uFR);
                        userComplete.Active = true;
                        
                        if(_reusableSql.UpsertUser(userComplete)){
                            return Ok();
                        }
                        throw new Exception("Failed to Add User");
                    }
                    throw new Exception("Failed to register user");
                }
                throw new Exception("User with this email already exists");
            }
            throw new Exception("Passwords do not match");
        }

        [HttpPut("ResetPassword")]
        public IActionResult ResetPassword(UserForLoginDTO userForSetPassword){
            if (_authHelper.SetPassword(userForSetPassword)){
                return Ok();
            }
            throw new Exception("Failed to update Password");
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public IActionResult Login(UserForLoginDTO uFL){
            string sqlForHashAndSalt = @"EXEC TutorialAppSchema.spLoginConfirmation_Get
                                        @Email = @EmailParam"; 

            DynamicParameters sqlParameters = new DynamicParameters();
            sqlParameters.Add("@EmailParam", uFL.Email, DbType.String);

            UserForLoginConfirmationDTO userForConfirmation = _dapper.LoadDataSingleWithParameters<UserForLoginConfirmationDTO>(sqlForHashAndSalt, sqlParameters);
            
            byte[] passwordHash = _authHelper.GetPasswordHash(uFL.Password, userForConfirmation.PasswordSalt);

            for(int i = 0; i < passwordHash.Length; i++){
                if (passwordHash[i] != userForConfirmation.PasswordHash[i]){
                    Console.WriteLine(i);
                    return StatusCode(401,"Incorrect Password");   
                }
            }

            string userIdSql = "SELECT UserId FROM TutorialAppSchema.Users WHERE Email = '" + uFL.Email + "'";

            int userId = _dapper.LoadDataSingle<int>(userIdSql);

            return Ok(new Dictionary<string, string>{
                {"token", _authHelper.CreateToken(userId)}
            });
        }

        [HttpGet("RefreshToken")]
        public string RefreshToken(){
            
            string sqlGetUserId = "SELECT UserId FROM TutorialAppSchema.Users WHERE UserId = '" + User.FindFirst("userId")?.Value + "'"; 
            
            int userId = _dapper.LoadDataSingle<int>(sqlGetUserId);

            return _authHelper.CreateToken(userId);
        }
    }
}