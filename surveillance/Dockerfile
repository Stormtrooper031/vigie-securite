# Contexte de build : racine du projet (pour inclure shared/)
#   docker build -f surveillance/Dockerfile .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY shared/Vigie.Shared/Vigie.Shared.csproj shared/Vigie.Shared/
COPY surveillance/Vigie.Scanner.csproj surveillance/
RUN dotnet restore surveillance/Vigie.Scanner.csproj
COPY shared/ shared/
COPY surveillance/ surveillance/
RUN dotnet publish surveillance/Vigie.Scanner.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Vigie.Scanner.dll"]
