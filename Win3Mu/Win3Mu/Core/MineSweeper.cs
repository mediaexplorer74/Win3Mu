using System;

namespace MineSweeper.Core
{
    public class MineSweeper
    {
        private readonly int _numberOfColumns;
        private readonly int _numberOfRows;
        private readonly MineField[,] _fields;

        public MineSweeper(int columns, int rows, int mines, int firstFieldX, int firstFieldY)
        {
            _numberOfColumns = columns;
            _numberOfRows = rows;

            _fields = new MineField[_numberOfColumns, _numberOfRows];

            for (var i = 0; i < _numberOfColumns; i++)
            {
                for (var j = 0; j < _numberOfRows; j++)
                {
                    _fields[i, j] = new MineField();
                }
            }

            CheckCoordinates(firstFieldX, firstFieldY);

            var random = new Random();

            for(var i = 0; i < mines; i++)
            {
                int x, y;
                do
                {
                    x = random.Next(0, _numberOfColumns);
                    y = random.Next(0, _numberOfRows);
                } while (_fields[x, y].HasMine || (x == firstFieldX && y == firstFieldY));
                _fields[x, y].HasMine = true;
            }
        }

        public MarkFieldStatus Mark(int x, int y)
        {
            CheckCoordinates(x,y);

            var field = _fields[x, y];
            field.IsMarked = !field.IsMarked;

            return field.IsMarked
                ? MarkFieldStatus.FieldIsMarked
                : MarkFieldStatus.FieldIsUnmarked;
        }

        public bool IsMarked(int x, int y)
        {
            CheckCoordinates(x,y);
            return _fields[x, y].IsMarked;
        }

        public bool HasMine(int x, int y)
        {
            CheckCoordinates(x,y);
            return _fields[x, y].HasMine;
        }

        public FieldStatus Open(int x, int y)
        {
            CheckCoordinates(x,y);
            var field = _fields[x, y];

            if (field.HasMine)
            {
                return FieldStatus.FieldIsMine;
            }

            switch (CountNearbyMines(x,y))
            {
                case 0: return FieldStatus.MinesNearby0;
                case 1: return FieldStatus.MinesNearby1;
                case 2: return FieldStatus.MinesNearby2;
                case 3: return FieldStatus.MinesNearby3;
                case 4: return FieldStatus.MinesNearby4;
                case 5: return FieldStatus.MinesNearby5;
                case 6: return FieldStatus.MinesNearby6;
                case 7: return FieldStatus.MinesNearby7;
                default: return FieldStatus.MinesNearby8;
            }
        }

        private int CountNearbyMines(int x, int y)
        {
            var mines = 0;

            for (var i = x - 1; i < x + 2; i++)
            {
                if (i < 0 || i >= _numberOfColumns)
                {
                    continue;
                }

                for (var j = y - 1; j < y + 2; j++)
                {
                    if (j < 0 || j >= _numberOfRows || (i == x && j == y))
                    {
                        continue;
                    }

                    if (_fields[i, j].HasMine)
                    {
                        mines++;
                    }
                }
            }

            return mines;
        }

        private void CheckCoordinates(int x, int y)
        {
            if (x < 0 || x >= _numberOfColumns || y < 0 || y >= _numberOfRows)
            {
                throw new ArgumentOutOfRangeException("One or more of the provided coordinates are invalid!");
            }
        }
    }
}
