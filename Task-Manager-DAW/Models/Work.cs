//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Task_Manager_DAW.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class Work
    {
        public int Id_works { get; set; }
        public int Id_user { get; set; }
        public int Id_project { get; set; }
        public string role { get; set; }
    
        public virtual Project Project { get; set; }
        public virtual User User { get; set; }
    }
}