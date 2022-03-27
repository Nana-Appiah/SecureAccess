using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

using PortSight;
using SecureAccess;
using PortSight.SecureAccess;
using PortSight.SecureAccess.ARObjects;
using PortSight.SecureAccess.ARDataServices;
using System.Threading.Tasks;
using System.Configuration;

using SecureAuth.Models;
using System.Web.Http.Cors;
using System.Web.Cors;

namespace SecureAuth.Controllers
{
    [EnableCors(origins: "https://localhost:7111", headers:"*",methods:"*")]
    public class UserController : ApiController
    {
       
        [HttpPost]
        public async Task<bool> User(string[] model)
        {
            var str = ConfigurationManager.AppSettings["connstring"].ToString();
            var conn = new ARConnection(str);
            conn.ConnectToCatalog();

            var o = ARHelper.AuthenticateUser(model[0],model[1],str, Functions.GetAES256EncryptionKey(),
                                               Functions.GetAES256InitializationVector(),Functions.GetAES256CipherStringFormat());
            if(o == ARAuthenticationResultsEnum.OK)
            {
                var user = new ARUser();
                user = conn.GetUserByLogin(model[0]);

                var u = new ARUserTicket(user);

                return true;
            }
            else { return false; }
        }

        [HttpGet]
        public bool isAuthorized(string[] data)
        {
            //username
            //resource alias (etas.admin or etas.student)
            //permission list (create , read,update, delete)
            try
            {
                var str = ConfigurationManager.AppSettings["connstring"].ToString();
                var conn = new ARConnection(str);
                conn.ConnectToCatalog();

                var user = new ARUser();
                user = conn.GetUserByLogin(data[0]);

                var u = new ARUserTicket(user);
                var membership = u.MembershipObjectAliases.Split(';');

                bool bln = Array.Exists(membership, x => x == data[1].ToString());

                //bool bln = ARHelper.IsAuthorized(data[0], data[1], data[2]);

                return bln;
            }
            catch (Exception x)
            {
                return false;
            }
        }

        //private bool IsAuthorized(ARUserTicket ticket, string resourcealias, string permissionalias)
        //{
        //    var str = ConfigurationManager.AppSettings["connstring"].ToString();
        //    var ARConn = new ARConnection(str);
        //    ARConn.ConnectToCatalog();

        //    if (ARHelper.IsAuthorized(ticket.Login, resourcealias, permissionalias))
        //        return true;
        //    else
        //    {
        //        // gets all operators authorized for this permission
        //        ARObject authorizedOperator;
        //        foreach (var authorizedOperator in GetAuthorisedOperators(ARConn.GetResourceByAlias(resourcealias).ObjectID))
        //        {
        //            foreach (string membership in ticket.MembershipObjectAliases.Split(";"))
        //            {
        //                if (!membership == "")
        //                {
        //                    AROperator arOperator;
        //                    if (!ARConn.GetGroupByAlias(membership) == null)
        //                    {
        //                        if (authorizedOperator.ObjectID == ARConn.GetGroupByAlias(membership).ObjectID)
        //                        {
        //                            arOperator = ARConn.GetOperatorByID(authorizedOperator.ObjectID);
        //                            return arOperator.IsAuthorized(resourcealias, permissionalias);
        //                        }
        //                    }
        //                    else if (!ARConn.GetRoleByAlias(membership) == null)
        //                    {
        //                        if (authorizedOperator.ObjectID == ARConn.GetRoleByAlias(membership).ObjectID)
        //                        {
        //                            arOperator = ARConn.GetOperatorByID(authorizedOperator.ObjectID);
        //                            return arOperator.IsAuthorized(resourcealias, permissionalias);
        //                        }
        //                    }
        //                }
        //            }
        //        }
        //    }
        //}

    }
}
