using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Helpers
{
    public class SpaceDelimitedStringJsonConverter : JsonConverter<string[]>
    {
        public override string[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            return reader.GetString().Split(' ');
        }

        public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.Aggregate((e, n) => $"{e} {n}"));
        }
    }
}
