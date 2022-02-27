using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;
//using Windows.Storage;
using Win3muRuntime;

namespace Win3mu
{
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();


            string arg0 = "SKI.exe";
            string arg1 = "";

            int r = API.Run(arg0, arg1, 1 /* SW_SHOWNORMAL */);
        }

       
    }
}
