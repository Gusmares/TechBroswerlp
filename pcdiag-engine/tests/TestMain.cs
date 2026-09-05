using System;

namespace PcDiag.Testing
{
    public static class TestMain
    {
        public static int Main(string[] args)
        {
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; }
            catch { }

            Console.WriteLine("PC Diagnostic Engine - suite de testes");
            Console.WriteLine("(unitarios, integracao, regressao e injecao de falha)");

            TestRunner runner = new TestRunner();

            RunGroup(runner, "CoreTests", CoreTests.Run);
            RunGroup(runner, "DiagnosticTests", DiagnosticTests.Run);
            RunGroup(runner, "CollectorTests", CollectorTests.Run);
            RunGroup(runner, "ChipsetTests", ChipsetTests.Run);
            RunGroup(runner, "IntegrationTests", IntegrationTests.Run);

            return runner.Report();
        }

        // Isola cada grupo de testes: uma excecao nao tratada em um teste
        // nao pode derrubar o processo inteiro antes que TestRunner.Report()
        // rode, nem impedir que os grupos seguintes sejam executados. A
        // excecao conta como falha do grupo (via TestRunner.Check) e a
        // suite sempre segue ate Report() ser chamado.
        private static void RunGroup(TestRunner runner, string groupName, Action<TestRunner> run)
        {
            try
            {
                run(runner);
            }
            catch (Exception ex)
            {
                runner.Check(groupName + ": excecao nao tratada interrompeu o grupo", false,
                    ex.GetType().Name + ": " + ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }
    }
}
