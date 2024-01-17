using System.Data;
using Dapper;
using DotnetAPI.Data;
using DotnetAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAPI.Controllers {


    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class PostController : ControllerBase{

        private readonly DataContextDapper _dapper;

        public PostController(IConfiguration config){
            _dapper = new DataContextDapper(config);
        }

        [HttpGet("Posts/{postId}/{userId}/{searchParam}")]
        public IEnumerable<Post> GetPosts(int postId = 0, int userId = 0, string searchParam = "None"){
            string sql = @"EXEC TutorialAppSchema.spPosts_Get";
            string parameters = "";
            
            DynamicParameters sqlParameters = new DynamicParameters();
            
            if (postId != 0){
                parameters += ", @PostId=@PostIdParam";
                sqlParameters.Add("@PostIdParam", postId, DbType.Int32);
            }
            if (userId != 0){
                parameters += ", @UserId=@UserIdParam";
                sqlParameters.Add("UserIdParam", userId, DbType.Int32);
            }
            if (searchParam.ToLower() != "none"){
                parameters += ", @SearchValue= @SearchParam";
                sqlParameters.Add("@SearchParam", searchParam, DbType.String);
            }
            if (parameters.Length > 0){
                sql += parameters.Substring(1);
            }
            return _dapper.LoadDataWithParameters<Post>(sql,sqlParameters);                            
        }

        [HttpGet("MyPosts")]
        public IEnumerable<Post> GetMyPosts(){
             string sql = @"EXEC TutorialAppSchema.spPosts_Get
                            @UserId = @UserIdParam";
            
            DynamicParameters sqlParameters = new DynamicParameters();
            sqlParameters.Add("@UserIdParam", this.User.FindFirst("userId")?.Value, DbType.Int32);
            
            return _dapper.LoadDataWithParameters<Post>(sql,sqlParameters);  
        }

        [HttpPut("UpsertPost")]
        public IActionResult UpsertPost(Post postToUpsert){

            string sql = @"TutorialAppSchema.sp_Posts_Upsert
                            @UserId = @UserIdParam,
                            @PostTitle = @PostTitleParam,
                            @PostContent = @PostContentParam";

            DynamicParameters sqlParameters = new DynamicParameters();
            sqlParameters.Add("@UserIdParam", this.User.FindFirst("userId")?.Value, DbType.Int32);
            sqlParameters.Add("@PostTitleParam",postToUpsert.PostTitle, DbType.String);
            sqlParameters.Add("@PostContentParam",postToUpsert.PostContent, DbType.String);
            
            if (postToUpsert.PostId > 0){
                sql += ", @PostId = @PostIdParam";
                sqlParameters.Add("@PostIdParam", postToUpsert.PostId, DbType.Int32);
            }                

            if (_dapper.ExecuteSqlWithParameters(sql, sqlParameters)){
                return Ok();
            } 
            throw new Exception("Failed to upsert post");
        }

        [HttpDelete("DeletePost/{postId}")]
        public IActionResult DeletePost(int postId){
            string sql = @"EXEC TutorialAppSchema.spPost_Delete
                            @PostId = @PostIdParam,
                            @UserId = @UserIdParam";

            DynamicParameters sqlParameters = new DynamicParameters();
            sqlParameters.Add("@UserIdParam", this.User.FindFirst("userId")?.Value, DbType.Int32);
            sqlParameters.Add("@PostIdParam", postId, DbType.Int32);
            
            if (_dapper.ExecuteSqlWithParameters(sql, sqlParameters)){
                return Ok();
            } 
            throw new Exception("Failed to delete post");
        }

    }
}