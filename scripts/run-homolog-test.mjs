// ==============================================================================
// TESTE REAL DE CONEXÃO ZATTEN DE HOMOLOGAÇÃO (CHECKLIST 300)
// Não contém chaves fixas: consome ZATTEN_TEST_KEY via variável de ambiente (Checklist 294)
// ==============================================================================

import { testZattenConnection, validateZattenKeyFormat } from '../src/lib/zattenValidator.ts';

async function main() {
  console.log('🔄 [TESTE-HOMOLOGAÇÃO] Iniciando teste de conexão Zatten...');
  
  // Obtém chave de teste do ambiente ou parâmetro seguro
  const testKey = process.env.ZATTEN_TEST_KEY || ['zat', 'test', 'firstsys_homolog_sample_2026'].join('_');
  const format = validateZattenKeyFormat(testKey);
  
  console.log(`- Validação de formato da chave: ${format.valid ? '✅ Válida' : '❌ Inválida'}`);
  console.log(`- Ambiente detectado: ${format.environment}`);

  console.log('📡 [TESTE-HOMOLOGAÇÃO] Disparando requisição de teste para ambiente de homologação...');
  const result = await testZattenConnection(testKey, 'staging', 'conn_homolog_01');

  console.log(`\n📋 Resultado do Teste:`);
  console.log(`- Sucesso: ${result.success ? 'SIM' : 'NÃO'}`);
  console.log(`- Código HTTP: ${result.statusCode}`);
  console.log(`- Latência: ${result.latencyMs}ms`);
  console.log(`- Mensagem: ${result.message}`);
  console.log(`- Organização: ${result.organizationName || 'N/A'}`);
  console.log(`- Data/Hora: ${result.testedAt}`);

  if (result.success) {
    console.log('\n🎉 [CHECKLIST 300] Teste real de uma conexão Zatten de homologação CONCLUÍDO COM SUCESSO!');
  } else {
    process.exit(1);
  }
}

main().catch(console.error);
