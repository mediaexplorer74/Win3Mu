using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//using MineSweeper.CustomControls;
//using MineSweeper.Core;

using Xamarin.Forms;
using Win3muRuntime;

namespace MineSweeper
{
    /*
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                MessageBox(IntPtr.Zero, "Usage: win3mu <programName> [/debug|/release] [/break] [/config:name]", "Win3mu", 0x10);
                return 1;
            }

            return API.Run(args[0], args.Skip(1).ToArray(), 1 /* SW_SHOWNORMAL */);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, string text, string caption, int options);
    }
    */

    public partial class MainPage
    {
        private const int rows = 10;
        private const int columns = 10;
        private const int mines = 10;
        private const string MinesLeftText = "Mines left: {0}";

        private ImageSource _blank;
        private ImageSource _mine;
        private ImageSource _nomine;
        private ImageSource _explodedmine;
        private ImageSource _flag;
        private ImageSource _1;
        private ImageSource _2;
        private ImageSource _3;
        private ImageSource _4;
        private ImageSource _5;
        private ImageSource _6;
        private ImageSource _7;
        private ImageSource _8;

        private MineSweeper.Core.MineSweeper _core;
        private int _minesLeft;

        private bool _runmode;

        public MainPage()
        {
            InitializeComponent();

            _runmode = true; // init =)

            _blank = ImageSource.FromResource("MineSweeper.Images.blank.png");
            _mine = ImageSource.FromResource("MineSweeper.Images.mine.png");
            _nomine = ImageSource.FromResource("MineSweeper.Images.nomine.png");
            _explodedmine = ImageSource.FromResource("MineSweeper.Images.explodedmine.png");
            _flag = ImageSource.FromResource("MineSweeper.Images.flag.png");
            _1 = ImageSource.FromResource("MineSweeper.Images.1.png");
            _2 = ImageSource.FromResource("MineSweeper.Images.2.png");
            _3 = ImageSource.FromResource("MineSweeper.Images.3.png");
            _4 = ImageSource.FromResource("MineSweeper.Images.4.png");
            _5 = ImageSource.FromResource("MineSweeper.Images.5.png");
            _6 = ImageSource.FromResource("MineSweeper.Images.6.png");
            _7 = ImageSource.FromResource("MineSweeper.Images.7.png");
            _8 = ImageSource.FromResource("MineSweeper.Images.8.png");
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();

            var tapGesture = new TapGestureRecognizer();
            tapGesture.NumberOfTapsRequired = 1;
            tapGesture.Tapped += MineButtonClicked;

            foreach (var child in MineGrid.Children)
            {
                var button = child as MineButton;
                button.Source = _blank;
                button.GestureRecognizers.Add(tapGesture);
            }

            MineGrid.SizeChanged += (sender, o) =>
                {
                    MineGrid.HeightRequest = MineGrid.Width;
                };

            ResetGame();
        }

        protected void NewGameClicked(object sender, EventArgs e)
        {
            ResetGame();
            _runmode = true; // start! =)
        }

        protected void MineButtonClicked(object sender, EventArgs e)
        {
            if (_runmode)
            {
                if (!DigButton.IsEnabled)
                {
                    OpenField(sender as MineButton);
                }

                else
                {
                    MarkField(sender as MineButton);
                }
            }
        }

        protected void SwitchToDig(object sender, EventArgs e)
        {
            if (_runmode)
            {
                DigButton.IsEnabled = false;
                FlagButton.IsEnabled = true;
            }
        }

        protected void SwitchToFlag(object sender, EventArgs e)
        {
            if (_runmode)
            {
                DigButton.IsEnabled = true;
                FlagButton.IsEnabled = false;
            }
        }

        private void ResetGame()
        {
            foreach (var child in MineGrid.Children)
            {
                var button = child as MineButton;
                button.IsEnabled = true;
                button.BackgroundColor = Color.Gray;
                button.Source = _blank;
            }
            _core = null;
            _minesLeft = mines;
            MinesLeftLabel.Text = String.Format(MinesLeftText, _minesLeft);
        }

        private void OpenField(MineButton button)
        {
            if(_core == null)
            {
                _core = new MineSweeper.Core.MineSweeper(columns, rows, mines, button.XPosition, button.YPosition);
            }
            
            if(_core.IsMarked(button.XPosition, button.YPosition))
            {
                return;
            }

            button.IsEnabled = false;
            button.BackgroundColor = Color.Silver;
            var status = _core.Open(button.XPosition, button.YPosition);

            switch(status)
            {
                case FieldStatus.FieldIsMine:
                    ServeGameOver(button);
                    return;
                case FieldStatus.MinesNearby0:
                    button.Source = _blank;
                    OpenNearbyFields(button);
                    break;
                case FieldStatus.MinesNearby1:
                    button.Source = _1;
                    break;
                case FieldStatus.MinesNearby2:
                    button.Source = _2;
                    break;
                case FieldStatus.MinesNearby3:
                    button.Source = _3;
                    break;
                case FieldStatus.MinesNearby4:
                    button.Source = _4;
                    break;
                case FieldStatus.MinesNearby5:
                    button.Source = _5;
                    break;
                case FieldStatus.MinesNearby6:
                    button.Source = _6;
                    break;
                case FieldStatus.MinesNearby7:
                    button.Source = _7;
                    break;
                default:
                    button.Source = _8;
                    break;
            }
            
            if(MineGrid.Children.OfType<MineButton>().Count(b => b.IsEnabled) == mines)
            {
                ServeGameWin();
            }
        }

        private void MarkField(MineButton button)
        {
            if(_core == null)
            {
                return;
            }

            var status = _core.Mark(button.XPosition, button.YPosition);

            if(status == MarkFieldStatus.FieldIsMarked)
            {
                _minesLeft--;
                MinesLeftLabel.Text = String.Format(MinesLeftText, _minesLeft > 0 ? _minesLeft : 0);
                button.Source = _flag;
            }
            else
            {
                _minesLeft++;
                MinesLeftLabel.Text = String.Format(MinesLeftText, _minesLeft > 0 ? _minesLeft : 0);
                button.Source = _blank;
            }
        }

        private void ServeGameOver(MineButton button)
        {
            foreach(var child in MineGrid.Children)
            {
                var b = child as MineButton;
                b.IsEnabled = false;
                b.BackgroundColor = Color.Silver;

                if(!_core.IsMarked(b.XPosition, b.YPosition))
                {
                    if(_core.HasMine(b.XPosition, b.YPosition))
                    {
                        b.Source = _mine;
                    }
                }
                else if(!_core.HasMine(b.XPosition, b.YPosition))
                {
                    b.Source = _nomine;
                }
            }

            button.Source = _explodedmine;
            DisplayAlert("Game over", "BOOM! You lose!", "OK");

            _runmode = false; // block Mine button =)
        }

        private void ServeGameWin()
        {
            foreach(var child in MineGrid.Children)
            {
                var button = child as MineButton;
                button.IsEnabled = false;

                if(!_core.IsMarked(button.XPosition, button.YPosition) &&
                    _core.HasMine(button.XPosition, button.YPosition))
                {
                    button.Source = _flag;
                }
            }

            MinesLeftLabel.Text = String.Format(MinesLeftText, 0);

            DisplayAlert("Game over", "You win!", "OK");

            _runmode = false; // block Mine button =)
        }

        private void OpenNearbyFields(MineButton button)
        {
            var nearbyButtons = GetNearbyButtons(button);
            
            foreach(var b in nearbyButtons)
            {
                OpenField(b);
            }
        }

        private List<MineButton> GetNearbyButtons(MineButton button)
        {
            if(!AreValidCoordinates(button.XPosition, button.YPosition))
            {
                return new List<MineButton>();
            }

            return MineGrid.Children
                .OfType<MineButton>()
                .Where(b => b.IsEnabled
                    && (b.XPosition != button.XPosition || b.YPosition != button.YPosition)
                    && b.XPosition > button.XPosition - 2
                    && b.XPosition < button.XPosition + 2
                    && b.YPosition > button.YPosition - 2
                    && b.YPosition < button.YPosition + 2)
                    .ToList();
        }

        private bool AreValidCoordinates(int x, int y)
        {
            return x >= 0
                && x < columns
                && y >= 0
                && y < rows;
        }
    }
}
