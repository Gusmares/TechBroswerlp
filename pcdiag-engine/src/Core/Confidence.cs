using System;

namespace PcDiag.Core
{
    // Confianca calculada, nunca escolhida a dedo (item 45).
    //
    // A regra e explicita e testavel. O uso tipico e:
    //
    //   Confidence.Build()
    //       .Authoritative()             // veio de API nativa / contador do kernel
    //       .AgreeingSource()            // segunda fonte independente concorda
    //       .PlausibleRange()            // valor dentro de faixa fisica possivel
    //       .Value                       // -> 90
    //
    // O teto e 99: nenhuma leitura de software sobre hardware de terceiro
    // merece 100%.
    public struct Confidence
    {
        public const int Min = 5;
        public const int Max = 99;
        private const int BaseScore = 50;

        private int _score;

        public static Confidence Build()
        {
            Confidence c = new Confidence();
            c._score = BaseScore;
            return c;
        }

        // Fonte primaria autoritativa: API nativa do Windows, contador do
        // kernel, ou o proprio dispositivo (SMART).
        public Confidence Authoritative()
        {
            _score += 20;
            return this;
        }

        // Cada fonte independente adicional que concorda. Limitado a duas
        // (+20 no total) - a terceira confirmacao agrega pouco.
        private int _agreeing;
        public Confidence AgreeingSource()
        {
            if (_agreeing < 2)
            {
                _agreeing++;
                _score += 10;
            }
            return this;
        }

        // Valor dentro de faixa fisicamente plausivel (ex: temperatura de CPU
        // entre 5 e 120 C). Um valor fora da faixa nao ganha esse bonus.
        public Confidence PlausibleRange()
        {
            _score += 10;
            return this;
        }

        // Fontes independentes discordam entre si.
        public Confidence Divergent()
        {
            _score -= 30;
            return this;
        }

        // Fonte declarativa reconhecidamente nao confiavel: campo SMBIOS
        // preenchido pelo fabricante (total de slots, tabela Type 9 de slots
        // PCIe), AdapterRAM de 32 bits.
        public Confidence UnreliableSource()
        {
            _score -= 20;
            return this;
        }

        // Amostra unica de grandeza volatil (uso instantaneo de CPU, RAM livre
        // em um dado milissegundo).
        public Confidence SingleVolatileSample()
        {
            _score -= 15;
            return this;
        }

        // Dado derivado de heuristica textual (ex: classificar GPU como
        // integrada pelo nome comercial) em vez de identificador estavel.
        public Confidence Heuristic()
        {
            _score -= 15;
            return this;
        }

        public int Value
        {
            get
            {
                if (_score < Min) return Min;
                if (_score > Max) return Max;
                return _score;
            }
        }

        // Confianca de um diagnostico composto: a do elo mais fraco, porque
        // uma conclusao nao pode ser mais confiavel que a pior evidencia que
        // a sustenta.
        public static int Combine(params int[] parts)
        {
            if (parts == null || parts.Length == 0) return Min;
            int lowest = Max;
            foreach (int p in parts)
            {
                if (p < lowest) lowest = p;
            }
            if (lowest < Min) return Min;
            if (lowest > Max) return Max;
            return lowest;
        }
    }
}
